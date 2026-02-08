/*
 * lblk-bench - minimal-overhead I/O benchmarking tool using libblkio
 *
 * Benchmarks vhost-user-blk backends (and other libblkio drivers) with
 * busy-loop polling, per-request latency tracking, and fio-style output.
 */

#define _GNU_SOURCE
#include <blkio.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── Constants ─────────────────────────────────────────────────────── */

#define VERSION "1.0.0"
#define HIST_BUCKETS 32  /* log2 histogram: bucket i = [2^i, 2^(i+1)) ns; 0 = <1us */
#define NS_PER_SEC   1000000000ULL
#define NS_PER_US    1000ULL
#define NS_PER_MS    1000000ULL

/* ── I/O pattern enum ──────────────────────────────────────────────── */

enum rw_mode {
	RW_READ,
	RW_WRITE,
	RW_RANDREAD,
	RW_RANDWRITE,
	RW_READWRITE,
	RW_RANDRW,
};

/* ── Per-request slot (passed as user_data) ────────────────────────── */

struct req_slot {
	uint64_t submit_ns;
	uint64_t offset;
	bool is_write;
	int index;
};

/* ── Per-worker stats ──────────────────────────────────────────────── */

struct worker_stats {
	uint64_t ios_done;
	uint64_t bytes_done;
	uint64_t read_ios;
	uint64_t write_ios;
	uint64_t read_bytes;
	uint64_t write_bytes;
	uint64_t errors;
	uint64_t flushes;
	uint64_t lat_min_ns;
	uint64_t lat_max_ns;
	uint64_t lat_sum_ns;
	uint64_t hist[HIST_BUCKETS];
};

/* ── Parsed arguments ──────────────────────────────────────────────── */

struct bench_args {
	const char *path;
	const char *driver;
	enum rw_mode rw;
	uint64_t bs;
	int iodepth;
	int numjobs;
	int runtime;
	uint64_t size;
	uint64_t offset;
	int rwmixread;
	int ramp_time;
	int sync_n;
	int queue_size;
	bool json_output;
};

/* ── Worker context ────────────────────────────────────────────────── */

struct worker_ctx {
	int job_index;
	struct blkioq *queue;
	struct blkio_mem_region region;
	struct bench_args *args;
	struct worker_stats stats;
	uint64_t prng_state;
	uint64_t seq_offset;
	int write_counter;
	/* timing */
	uint64_t start_ns;
	uint64_t ramp_end_ns;
	uint64_t end_ns;
};

/* ── CPU usage ─────────────────────────────────────────────────────── */

struct cpu_usage {
	uint64_t utime_ticks;
	uint64_t stime_ticks;
	uint64_t wall_ns;
};

/* ── Helpers ───────────────────────────────────────────────────────── */

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

static int hist_bucket(uint64_t lat_ns)
{
	if (lat_ns < NS_PER_US)
		return 0;
	/* bucket i covers [2^(i-1) us, 2^i us) for i >= 1, stored as ns */
	int b = 1;
	uint64_t threshold = 2 * NS_PER_US;
	while (b < HIST_BUCKETS - 1 && lat_ns >= threshold) {
		b++;
		threshold <<= 1;
	}
	return b;
}

static uint64_t hist_bucket_upper_ns(int b)
{
	if (b == 0)
		return NS_PER_US;
	return NS_PER_US << b;
}

static uint64_t percentile_from_hist(const uint64_t *hist, uint64_t total, double pct)
{
	uint64_t target = (uint64_t)ceil((double)total * pct / 100.0);
	uint64_t cumulative = 0;
	for (int i = 0; i < HIST_BUCKETS; i++) {
		cumulative += hist[i];
		if (cumulative >= target)
			return hist_bucket_upper_ns(i);
	}
	return hist_bucket_upper_ns(HIST_BUCKETS - 1);
}

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

static void stats_reset(struct worker_stats *s)
{
	memset(s, 0, sizeof(*s));
	s->lat_min_ns = UINT64_MAX;
}

static void stats_record(struct worker_stats *s, uint64_t lat_ns, uint64_t bs, bool is_write)
{
	s->ios_done++;
	s->bytes_done += bs;
	if (is_write) {
		s->write_ios++;
		s->write_bytes += bs;
	} else {
		s->read_ios++;
		s->read_bytes += bs;
	}
	s->lat_sum_ns += lat_ns;
	if (lat_ns < s->lat_min_ns) s->lat_min_ns = lat_ns;
	if (lat_ns > s->lat_max_ns) s->lat_max_ns = lat_ns;
	s->hist[hist_bucket(lat_ns)]++;
}

static void stats_merge(struct worker_stats *dst, const struct worker_stats *src)
{
	dst->ios_done += src->ios_done;
	dst->bytes_done += src->bytes_done;
	dst->read_ios += src->read_ios;
	dst->write_ios += src->write_ios;
	dst->read_bytes += src->read_bytes;
	dst->write_bytes += src->write_bytes;
	dst->errors += src->errors;
	dst->flushes += src->flushes;
	dst->lat_sum_ns += src->lat_sum_ns;
	if (src->lat_min_ns < dst->lat_min_ns) dst->lat_min_ns = src->lat_min_ns;
	if (src->lat_max_ns > dst->lat_max_ns) dst->lat_max_ns = src->lat_max_ns;
	for (int i = 0; i < HIST_BUCKETS; i++)
		dst->hist[i] += src->hist[i];
}

/* ── Workload generation ───────────────────────────────────────────── */

static bool mode_is_random(enum rw_mode m)
{
	return m == RW_RANDREAD || m == RW_RANDWRITE || m == RW_RANDRW;
}

static bool mode_is_mixed(enum rw_mode m)
{
	return m == RW_READWRITE || m == RW_RANDRW;
}

static bool mode_is_write_only(enum rw_mode m)
{
	return m == RW_WRITE || m == RW_RANDWRITE;
}

static uint64_t next_offset(struct worker_ctx *w)
{
	struct bench_args *a = w->args;
	uint64_t io_range = a->size;
	uint64_t n_blocks = io_range / a->bs;

	if (n_blocks == 0) n_blocks = 1;

	if (mode_is_random(a->rw)) {
		uint64_t block = xorshift64(&w->prng_state) % n_blocks;
		return a->offset + block * a->bs;
	}
	/* sequential */
	uint64_t off = a->offset + w->seq_offset;
	w->seq_offset += a->bs;
	if (w->seq_offset >= io_range)
		w->seq_offset = 0;
	return off;
}

static bool next_is_write(struct worker_ctx *w)
{
	struct bench_args *a = w->args;
	if (mode_is_write_only(a->rw))
		return true;
	if (!mode_is_mixed(a->rw))
		return false;
	/* mixed: write with probability (100 - rwmixread)% */
	return (xorshift64(&w->prng_state) % 100) >= (uint64_t)a->rwmixread;
}

/* ── I/O loop (hot path) ──────────────────────────────────────────── */

static void *worker_thread(void *arg)
{
	struct worker_ctx *w = arg;
	struct bench_args *a = w->args;
	struct blkioq *q = w->queue;
	unsigned char *base = (unsigned char *)w->region.addr;
	int depth = a->iodepth;

	struct req_slot *slots = calloc(depth, sizeof(struct req_slot));
	struct blkio_completion *comps = calloc(depth, sizeof(struct blkio_completion));
	if (!slots || !comps) {
		fprintf(stderr, "worker %d: alloc failed\n", w->job_index);
		free(slots);
		free(comps);
		return NULL;
	}

	stats_reset(&w->stats);
	struct timespec zero_timeout = {0, 0};
	bool ramped = (a->ramp_time == 0);

	/* Pre-fill: queue iodepth initial requests */
	for (int i = 0; i < depth; i++) {
		slots[i].index = i;
		slots[i].is_write = next_is_write(w);
		slots[i].offset = next_offset(w);
		slots[i].submit_ns = now_ns();

		void *buf = base + (size_t)i * a->bs;
		if (slots[i].is_write)
			blkioq_write(q, slots[i].offset, buf, a->bs, &slots[i], 0);
		else
			blkioq_read(q, slots[i].offset, buf, a->bs, &slots[i], 0);
	}

	w->start_ns = now_ns();
	w->ramp_end_ns = w->start_ns + (uint64_t)a->ramp_time * NS_PER_SEC;
	w->end_ns = w->start_ns + (uint64_t)(a->ramp_time + a->runtime) * NS_PER_SEC;

	/* Main I/O loop */
	for (;;) {
		int n = blkioq_do_io(q, comps, 0, depth, &zero_timeout);
		if (n < 0) {
			w->stats.errors++;
			break;
		}

		uint64_t t = now_ns();

		/* Check ramp */
		if (!ramped && t >= w->ramp_end_ns) {
			stats_reset(&w->stats);
			ramped = true;
		}

		/* Check end */
		if (t >= w->end_ns) {
			/* drain: don't requeue, just process completions */
			for (int i = 0; i < n; i++) {
				struct req_slot *s = comps[i].user_data;
				if (!s) continue; /* flush completion */
				if (comps[i].ret != 0) {
					w->stats.errors++;
					continue;
				}
				uint64_t lat = t - s->submit_ns;
				stats_record(&w->stats, lat, a->bs, s->is_write);
			}
			break;
		}

		for (int i = 0; i < n; i++) {
			struct req_slot *s = comps[i].user_data;
			if (!s) continue; /* flush completion */
			if (comps[i].ret != 0) {
				w->stats.errors++;
				/* still re-queue to maintain depth */
			} else {
				uint64_t lat = t - s->submit_ns;
				stats_record(&w->stats, lat, a->bs, s->is_write);
			}

			/* flush after N writes */
			if (a->sync_n > 0 && s->is_write) {
				w->write_counter++;
				if (w->write_counter >= a->sync_n) {
					w->write_counter = 0;
					blkioq_flush(q, NULL, 0);
					w->stats.flushes++;
				}
			}

			/* Re-queue */
			s->is_write = next_is_write(w);
			s->offset = next_offset(w);
			s->submit_ns = now_ns();

			void *buf = base + (size_t)s->index * a->bs;
			if (s->is_write)
				blkioq_write(q, s->offset, buf, a->bs, s, 0);
			else
				blkioq_read(q, s->offset, buf, a->bs, s, 0);
		}
	}

	free(slots);
	free(comps);
	return NULL;
}

/* ── CPU usage from /proc/self/stat ────────────────────────────────── */

static void read_cpu_usage(struct cpu_usage *c)
{
	c->wall_ns = now_ns();
	FILE *f = fopen("/proc/self/stat", "r");
	if (!f) {
		c->utime_ticks = 0;
		c->stime_ticks = 0;
		return;
	}
	/* Fields: pid comm state ppid ... field14=utime field15=stime */
	unsigned long utime = 0, stime = 0;
	int scanned = fscanf(f,
		"%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u "
		"%*u %*u %*u %lu %lu",
		&utime, &stime);
	fclose(f);
	if (scanned == 2) {
		c->utime_ticks = utime;
		c->stime_ticks = stime;
	}
}

/* ── Size parsing ──────────────────────────────────────────────────── */

static int parse_size(const char *str, uint64_t *out)
{
	char *end;
	errno = 0;
	double val = strtod(str, &end);
	if (errno || end == str || val < 0)
		return -1;
	uint64_t mult = 1;
	switch (*end) {
	case 'k': case 'K': mult = 1024; end++; break;
	case 'm': case 'M': mult = 1024 * 1024; end++; break;
	case 'g': case 'G': mult = 1024ULL * 1024 * 1024; end++; break;
	case 't': case 'T': mult = 1024ULL * 1024 * 1024 * 1024; end++; break;
	case '\0': break;
	default: return -1;
	}
	if (*end != '\0')
		return -1;
	*out = (uint64_t)(val * (double)mult);
	return 0;
}

static enum rw_mode parse_rw(const char *str)
{
	if (!strcmp(str, "read")) return RW_READ;
	if (!strcmp(str, "write")) return RW_WRITE;
	if (!strcmp(str, "randread")) return RW_RANDREAD;
	if (!strcmp(str, "randwrite")) return RW_RANDWRITE;
	if (!strcmp(str, "readwrite") || !strcmp(str, "rw")) return RW_READWRITE;
	if (!strcmp(str, "randrw")) return RW_RANDRW;
	fprintf(stderr, "error: unknown --rw mode '%s'\n", str);
	exit(1);
}

static const char *rw_name(enum rw_mode m)
{
	switch (m) {
	case RW_READ:      return "read";
	case RW_WRITE:     return "write";
	case RW_RANDREAD:  return "randread";
	case RW_RANDWRITE: return "randwrite";
	case RW_READWRITE: return "readwrite";
	case RW_RANDRW:    return "randrw";
	}
	return "unknown";
}

/* ── Output formatting ─────────────────────────────────────────────── */

static void format_size(uint64_t bytes, char *buf, size_t len)
{
	if (bytes >= 1024ULL * 1024 * 1024 && bytes % (1024ULL * 1024 * 1024) == 0)
		snprintf(buf, len, "%lug", (unsigned long)(bytes / (1024ULL * 1024 * 1024)));
	else if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0)
		snprintf(buf, len, "%lum", (unsigned long)(bytes / (1024 * 1024)));
	else if (bytes >= 1024 && bytes % 1024 == 0)
		snprintf(buf, len, "%luk", (unsigned long)(bytes / 1024));
	else
		snprintf(buf, len, "%lu", (unsigned long)bytes);
}

static void format_iops(double iops, char *buf, size_t len)
{
	if (iops >= 1e6)
		snprintf(buf, len, "%.1fM", iops / 1e6);
	else if (iops >= 1e4)
		snprintf(buf, len, "%.1fk", iops / 1e3);
	else if (iops >= 1e3)
		snprintf(buf, len, "%.2fk", iops / 1e3);
	else
		snprintf(buf, len, "%.0f", iops);
}

static void print_human_output(struct bench_args *a, struct worker_stats *total,
			       double wall_sec, struct cpu_usage *cpu_before,
			       struct cpu_usage *cpu_after)
{
	double iops = (double)total->ios_done / wall_sec;
	double bw_bytes = (double)total->bytes_done / wall_sec;
	double bw_mib = bw_bytes / (1024.0 * 1024.0);
	double bw_mb = bw_bytes / 1e6;

	char iops_str[32];
	format_iops(iops, iops_str, sizeof(iops_str));

	char bs_str[32];
	format_size(a->bs, bs_str, sizeof(bs_str));
	printf("lblk-bench: rw=%s, bs=%s, iodepth=%d, numjobs=%d, runtime=%ds\n",
	       rw_name(a->rw), bs_str, a->iodepth, a->numjobs, a->runtime);

	/* Determine latency display unit based on p50 (like fio) */
	const char *lat_unit;
	double lat_div;
	uint64_t p50_ns = total->ios_done > 0
		? percentile_from_hist(total->hist, total->ios_done, 50.0)
		: 0;
	if (p50_ns < NS_PER_US) {
		lat_unit = "nsec";
		lat_div = 1.0;
	} else if (p50_ns < NS_PER_MS) {
		lat_unit = "usec";
		lat_div = (double)NS_PER_US;
	} else {
		lat_unit = "msec";
		lat_div = (double)NS_PER_MS;
	}

	/* Print per-direction stats */
	bool has_read = total->read_ios > 0;
	bool has_write = total->write_ios > 0;

	if (has_read && has_write) {
		double r_iops = (double)total->read_ios / wall_sec;
		double w_iops = (double)total->write_ios / wall_sec;
		double r_bw = (double)total->read_bytes / wall_sec;
		double w_bw = (double)total->write_bytes / wall_sec;
		char r_iops_str[32], w_iops_str[32];
		format_iops(r_iops, r_iops_str, sizeof(r_iops_str));
		format_iops(w_iops, w_iops_str, sizeof(w_iops_str));
		printf("  read:  IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n",
		       r_iops_str, r_bw / (1024.0 * 1024.0), r_bw / 1e6);
		printf("  write: IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n",
		       w_iops_str, w_bw / (1024.0 * 1024.0), w_bw / 1e6);
	} else {
		const char *dir = has_write ? "write" : "read";
		printf("  %s: IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n",
		       dir, iops_str, bw_mib, bw_mb);
	}

	if (total->ios_done > 0) {
		double avg_lat = (double)total->lat_sum_ns / (double)total->ios_done / lat_div;
		double min_lat = (double)total->lat_min_ns / lat_div;
		double max_lat = (double)total->lat_max_ns / lat_div;

		printf("    lat (%s): min=%.1f, max=%.1f, avg=%.1f\n",
		       lat_unit, min_lat, max_lat, avg_lat);

		static const double pcts[] = {1, 5, 10, 50, 90, 99, 99.9, 99.99};
		static const int row_start[] = {0, 3, 6};
		static const int row_len[] = {3, 3, 2};
		printf("    lat percentiles (%s):\n", lat_unit);
		for (int r = 0; r < 3; r++) {
			printf("     |");
			for (int j = row_start[r]; j < row_start[r] + row_len[r]; j++) {
				uint64_t val_ns = percentile_from_hist(total->hist, total->ios_done, pcts[j]);
				long val = (long)(val_ns / (uint64_t)lat_div);
				if (j == 7)
					printf(" %5.2fth=[%5ld]", pcts[j], val);
				else
					printf(" %5.2fth=[%5ld],", pcts[j], val);
			}
			printf("\n");
		}
	}

	/* CPU usage */
	long ticks_per_sec = sysconf(_SC_CLK_TCK);
	if (ticks_per_sec > 0) {
		double wall_s = (double)(cpu_after->wall_ns - cpu_before->wall_ns) / (double)NS_PER_SEC;
		double usr = (double)(cpu_after->utime_ticks - cpu_before->utime_ticks) / (double)ticks_per_sec;
		double sys = (double)(cpu_after->stime_ticks - cpu_before->stime_ticks) / (double)ticks_per_sec;
		if (wall_s > 0) {
			printf("  cpu: usr=%.1f%%, sys=%.1f%%\n",
			       usr / wall_s * 100.0, sys / wall_s * 100.0);
		}
	}

	printf("  ios: total=%lu, errors=%lu, flushes=%lu\n",
	       (unsigned long)total->ios_done,
	       (unsigned long)total->errors,
	       (unsigned long)total->flushes);
}

static void print_json_output(struct bench_args *a, struct worker_stats *total,
			      double wall_sec, struct cpu_usage *cpu_before,
			      struct cpu_usage *cpu_after)
{
	double iops = (double)total->ios_done / wall_sec;
	double bw_bytes = (double)total->bytes_done / wall_sec;

	printf("{\n");
	printf("  \"job\": {\n");
	printf("    \"rw\": \"%s\",\n", rw_name(a->rw));
	printf("    \"bs\": %lu,\n", (unsigned long)a->bs);
	printf("    \"iodepth\": %d,\n", a->iodepth);
	printf("    \"numjobs\": %d,\n", a->numjobs);
	printf("    \"runtime\": %d,\n", a->runtime);
	printf("    \"driver\": \"%s\"\n", a->driver);
	printf("  },\n");

	printf("  \"iops\": %.2f,\n", iops);
	printf("  \"bw_bytes\": %.0f,\n", bw_bytes);
	printf("  \"read_iops\": %.2f,\n", (double)total->read_ios / wall_sec);
	printf("  \"write_iops\": %.2f,\n", (double)total->write_ios / wall_sec);
	printf("  \"read_bw_bytes\": %.0f,\n", (double)total->read_bytes / wall_sec);
	printf("  \"write_bw_bytes\": %.0f,\n", (double)total->write_bytes / wall_sec);
	printf("  \"ios_total\": %lu,\n", (unsigned long)total->ios_done);
	printf("  \"read_ios\": %lu,\n", (unsigned long)total->read_ios);
	printf("  \"write_ios\": %lu,\n", (unsigned long)total->write_ios);
	printf("  \"errors\": %lu,\n", (unsigned long)total->errors);
	printf("  \"flushes\": %lu,\n", (unsigned long)total->flushes);

	printf("  \"lat_ns\": {\n");
	if (total->ios_done > 0) {
		printf("    \"min\": %lu,\n", (unsigned long)total->lat_min_ns);
		printf("    \"max\": %lu,\n", (unsigned long)total->lat_max_ns);
		printf("    \"mean\": %.0f,\n", (double)total->lat_sum_ns / (double)total->ios_done);
		printf("    \"percentiles\": {\n");
		static const double pcts[] = {1, 5, 10, 50, 90, 99, 99.9, 99.99};
		for (int i = 0; i < 8; i++) {
			uint64_t val = percentile_from_hist(total->hist, total->ios_done, pcts[i]);
			printf("      \"p%.2f\": %lu%s\n",
			       pcts[i], (unsigned long)val, i < 7 ? "," : "");
		}
		printf("    }\n");
	} else {
		printf("    \"min\": 0,\n");
		printf("    \"max\": 0,\n");
		printf("    \"mean\": 0\n");
	}
	printf("  },\n");

	long ticks_per_sec = sysconf(_SC_CLK_TCK);
	double wall_s = (double)(cpu_after->wall_ns - cpu_before->wall_ns) / (double)NS_PER_SEC;
	double usr_pct = 0, sys_pct = 0;
	if (ticks_per_sec > 0 && wall_s > 0) {
		usr_pct = (double)(cpu_after->utime_ticks - cpu_before->utime_ticks) / (double)ticks_per_sec / wall_s * 100.0;
		sys_pct = (double)(cpu_after->stime_ticks - cpu_before->stime_ticks) / (double)ticks_per_sec / wall_s * 100.0;
	}
	printf("  \"cpu\": { \"usr\": %.2f, \"sys\": %.2f }\n", usr_pct, sys_pct);
	printf("}\n");
}

/* ── Usage ─────────────────────────────────────────────────────────── */

static void usage(void)
{
	fprintf(stderr,
"Usage: lblk-bench --path PATH --rw MODE [options]\n"
"\n"
"Required:\n"
"  --path PATH           Device/socket path (meaning depends on --driver)\n"
"  --rw MODE             I/O pattern: read, write, randread, randwrite,\n"
"                        readwrite, randrw\n"
"\n"
"Workload options:\n"
"  --bs SIZE             Block size (default: 4k)\n"
"  --iodepth N           Outstanding I/Os per queue (default: 1)\n"
"  --numjobs N           Parallel jobs/queues (default: 1)\n"
"  --runtime SEC         Duration in seconds (default: 10)\n"
"  --size SIZE           I/O region size per job (default: device capacity)\n"
"  --offset SIZE         Starting offset for I/O (default: 0)\n"
"  --rwmixread PCT       Read percentage for mixed workloads (default: 50)\n"
"  --ramp_time SEC       Warmup seconds before measuring (default: 0)\n"
"  --sync N              Flush every N writes; 0=disabled (default: 0)\n"
"\n"
"libblkio options:\n"
"  --driver NAME         libblkio driver (default: virtio-blk-vhost-user)\n"
"  --queue-size N        Virtio queue size (default: 256)\n"
"\n"
"Output options:\n"
"  --output-format FMT   Output format: normal, json (default: normal)\n"
"\n"
"  --help                Show this help\n"
"  --version             Show version\n"
	);
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
	struct bench_args args = {
		.path = NULL,
		.driver = "virtio-blk-vhost-user",
		.rw = RW_READ,
		.bs = 4096,
		.iodepth = 1,
		.numjobs = 1,
		.runtime = 10,
		.size = 0,
		.offset = 0,
		.rwmixread = 50,
		.ramp_time = 0,
		.sync_n = 0,
		.queue_size = 256,
		.json_output = false,
	};
	bool rw_set = false;

	static struct option long_options[] = {
		{"path",          required_argument, 0, 'p'},
		{"rw",            required_argument, 0, 'r'},
		{"bs",            required_argument, 0, 'b'},
		{"iodepth",       required_argument, 0, 'd'},
		{"numjobs",       required_argument, 0, 'j'},
		{"runtime",       required_argument, 0, 't'},
		{"size",          required_argument, 0, 's'},
		{"offset",        required_argument, 0, 'o'},
		{"rwmixread",     required_argument, 0, 'm'},
		{"ramp_time",     required_argument, 0, 'R'},
		{"sync",          required_argument, 0, 'S'},
		{"driver",        required_argument, 0, 'D'},
		{"queue-size",    required_argument, 0, 'Q'},
		{"output-format", required_argument, 0, 'F'},
		{"help",          no_argument,       0, 'h'},
		{"version",       no_argument,       0, 'V'},
		{0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p': args.path = optarg; break;
		case 'r': args.rw = parse_rw(optarg); rw_set = true; break;
		case 'b':
			if (parse_size(optarg, &args.bs) < 0) {
				fprintf(stderr, "error: invalid --bs '%s'\n", optarg);
				return 1;
			}
			break;
		case 'd': args.iodepth = atoi(optarg); break;
		case 'j': args.numjobs = atoi(optarg); break;
		case 't': args.runtime = atoi(optarg); break;
		case 's':
			if (parse_size(optarg, &args.size) < 0) {
				fprintf(stderr, "error: invalid --size '%s'\n", optarg);
				return 1;
			}
			break;
		case 'o':
			if (parse_size(optarg, &args.offset) < 0) {
				fprintf(stderr, "error: invalid --offset '%s'\n", optarg);
				return 1;
			}
			break;
		case 'm': args.rwmixread = atoi(optarg); break;
		case 'R': args.ramp_time = atoi(optarg); break;
		case 'S': args.sync_n = atoi(optarg); break;
		case 'D': args.driver = optarg; break;
		case 'Q': args.queue_size = atoi(optarg); break;
		case 'F':
			if (!strcmp(optarg, "json"))
				args.json_output = true;
			else if (strcmp(optarg, "normal")) {
				fprintf(stderr, "error: unknown --output-format '%s'\n", optarg);
				return 1;
			}
			break;
		case 'h': usage(); return 0;
		case 'V': printf("lblk-bench %s\n", VERSION); return 0;
		default: usage(); return 1;
		}
	}

	/* Validate required args */
	if (!args.path) {
		fprintf(stderr, "error: --path is required\n");
		usage();
		return 1;
	}
	if (!rw_set) {
		fprintf(stderr, "error: --rw is required\n");
		usage();
		return 1;
	}

	/* Validate values */
	if (args.bs < 512 || (args.bs & (args.bs - 1)) != 0) {
		fprintf(stderr, "error: --bs must be >= 512 and a power of 2\n");
		return 1;
	}
	if (args.iodepth < 1) {
		fprintf(stderr, "error: --iodepth must be >= 1\n");
		return 1;
	}
	if (args.numjobs < 1) {
		fprintf(stderr, "error: --numjobs must be >= 1\n");
		return 1;
	}
	if (args.runtime < 1) {
		fprintf(stderr, "error: --runtime must be >= 1\n");
		return 1;
	}
	if (args.rwmixread < 0 || args.rwmixread > 100) {
		fprintf(stderr, "error: --rwmixread must be 0-100\n");
		return 1;
	}

	/* ── Create and connect blkio instance ── */
	struct blkio *b = NULL;
	int ret;

	ret = blkio_create(args.driver, &b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_create(%s): %s\n",
			args.driver, blkio_get_error_msg());
		return 1;
	}

	ret = blkio_set_str(b, "path", args.path);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_set_str(path): %s\n",
			blkio_get_error_msg());
		blkio_destroy(&b);
		return 1;
	}

	ret = blkio_connect(b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_connect: %s\n",
			blkio_get_error_msg());
		blkio_destroy(&b);
		return 1;
	}

	/* Query capacity for default --size */
	uint64_t capacity = 0;
	blkio_get_uint64(b, "capacity", &capacity);
	if (args.size == 0) {
		if (capacity == 0) {
			fprintf(stderr, "error: device capacity is 0 and --size not set\n");
			blkio_destroy(&b);
			return 1;
		}
		args.size = capacity - args.offset;
	}

	/* Set queue properties (may fail for some drivers — that's OK) */
	blkio_set_int(b, "num-queues", args.numjobs);
	blkio_set_int(b, "queue-size", args.queue_size);

	ret = blkio_start(b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_start: %s\n",
			blkio_get_error_msg());
		blkio_destroy(&b);
		return 1;
	}

	/* ── Set up workers ── */
	struct worker_ctx *workers = calloc(args.numjobs, sizeof(struct worker_ctx));
	pthread_t *threads = calloc(args.numjobs, sizeof(pthread_t));
	if (!workers || !threads) {
		fprintf(stderr, "error: alloc failed\n");
		blkio_destroy(&b);
		return 1;
	}

	size_t region_size = (size_t)args.iodepth * args.bs;

	for (int i = 0; i < args.numjobs; i++) {
		workers[i].job_index = i;
		workers[i].args = &args;
		workers[i].prng_state = 0x853c49e6748fea9bULL ^ (uint64_t)(i + 1);
		workers[i].seq_offset = 0;
		workers[i].write_counter = 0;

		ret = blkio_alloc_mem_region(b, &workers[i].region, region_size);
		if (ret < 0) {
			fprintf(stderr, "error: blkio_alloc_mem_region (job %d): %s\n",
				i, blkio_get_error_msg());
			/* cleanup already allocated regions */
			for (int j = 0; j < i; j++) {
				blkio_unmap_mem_region(b, &workers[j].region);
				blkio_free_mem_region(b, &workers[j].region);
			}
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}

		ret = blkio_map_mem_region(b, &workers[i].region);
		if (ret < 0) {
			fprintf(stderr, "error: blkio_map_mem_region (job %d): %s\n",
				i, blkio_get_error_msg());
			blkio_free_mem_region(b, &workers[i].region);
			for (int j = 0; j < i; j++) {
				blkio_unmap_mem_region(b, &workers[j].region);
				blkio_free_mem_region(b, &workers[j].region);
			}
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}

		workers[i].queue = blkio_get_queue(b, i);
		if (!workers[i].queue) {
			fprintf(stderr, "error: blkio_get_queue(%d) returned NULL\n", i);
			for (int j = 0; j <= i; j++) {
				blkio_unmap_mem_region(b, &workers[j].region);
				blkio_free_mem_region(b, &workers[j].region);
			}
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}
	}

	/* ── Run benchmark ── */
	struct cpu_usage cpu_before, cpu_after;
	read_cpu_usage(&cpu_before);

	for (int i = 0; i < args.numjobs; i++) {
		ret = pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
		if (ret) {
			fprintf(stderr, "error: pthread_create (job %d): %s\n",
				i, strerror(ret));
			/* signal already-running threads to stop by adjusting end_ns */
			uint64_t t = now_ns();
			for (int j = 0; j < i; j++) {
				workers[j].end_ns = t;
				pthread_join(threads[j], NULL);
			}
			for (int j = 0; j < args.numjobs; j++) {
				blkio_unmap_mem_region(b, &workers[j].region);
				blkio_free_mem_region(b, &workers[j].region);
			}
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}
	}

	for (int i = 0; i < args.numjobs; i++)
		pthread_join(threads[i], NULL);

	read_cpu_usage(&cpu_after);

	/* ── Aggregate stats ── */
	struct worker_stats total;
	stats_reset(&total);
	for (int i = 0; i < args.numjobs; i++)
		stats_merge(&total, &workers[i].stats);

	double wall_sec = (double)args.runtime;

	/* ── Print results ── */
	if (args.json_output)
		print_json_output(&args, &total, wall_sec, &cpu_before, &cpu_after);
	else
		print_human_output(&args, &total, wall_sec, &cpu_before, &cpu_after);

	/* ── Cleanup ── */
	for (int i = 0; i < args.numjobs; i++) {
		blkio_unmap_mem_region(b, &workers[i].region);
		blkio_free_mem_region(b, &workers[i].region);
	}
	free(workers);
	free(threads);
	blkio_destroy(&b);

	return 0;
}
