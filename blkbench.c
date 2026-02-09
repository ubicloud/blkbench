/*
 * blkbench - minimal-overhead I/O benchmarking tool using libblkio
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

#define VERSION	     "1.0.0"
#define HIST_BUCKETS 32 /* log2 histogram: bucket i = [2^i, 2^(i+1)) ns; 0 = <1us */
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
	RW_VERIFY_FLUSH,
	RW_VERIFY_PIPELINE,
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
	/* Counters read by reporter thread while workers run — must be atomic.
	 * All accesses use memory_order_relaxed (single writer per field). */
	_Atomic uint64_t ios_done;
	_Atomic uint64_t bytes_done;
	_Atomic uint64_t read_ios;
	_Atomic uint64_t write_ios;
	_Atomic uint64_t read_bytes;
	_Atomic uint64_t write_bytes;
	/* Remaining fields: only read after workers are joined */
	uint64_t errors;
	uint64_t flushes;
	uint64_t lat_min_ns;
	uint64_t lat_max_ns;
	uint64_t lat_sum_ns;
	uint64_t hist[HIST_BUCKETS];
};

/* Relaxed helpers for single-writer atomic counters */
#define STAT_LOAD(field)       atomic_load_explicit(&(field), memory_order_relaxed)
#define STAT_STORE(field, val) atomic_store_explicit(&(field), (val), memory_order_relaxed)
#define STAT_ADD(field, val)   STAT_STORE(field, STAT_LOAD(field) + (val))
#define STAT_INC(field)	       STAT_ADD(field, 1)

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
	int queue_size; /* set to iodepth automatically */
	bool json_output;
	int direct;
	int verify_min_sectors;
	int verify_max_sectors;
	bool verify_inject_fault;
	int eta_interval; /* seconds between progress lines; 0 = disabled */
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
	STAT_STORE(s->ios_done, 0);
	STAT_STORE(s->bytes_done, 0);
	STAT_STORE(s->read_ios, 0);
	STAT_STORE(s->write_ios, 0);
	STAT_STORE(s->read_bytes, 0);
	STAT_STORE(s->write_bytes, 0);
	s->errors = 0;
	s->flushes = 0;
	s->lat_min_ns = UINT64_MAX;
	s->lat_max_ns = 0;
	s->lat_sum_ns = 0;
	memset(s->hist, 0, sizeof(s->hist));
}

static void stats_record(struct worker_stats *s, uint64_t lat_ns, uint64_t bs, bool is_write)
{
	STAT_INC(s->ios_done);
	STAT_ADD(s->bytes_done, bs);
	if (is_write) {
		STAT_INC(s->write_ios);
		STAT_ADD(s->write_bytes, bs);
	} else {
		STAT_INC(s->read_ios);
		STAT_ADD(s->read_bytes, bs);
	}
	s->lat_sum_ns += lat_ns;
	if (lat_ns < s->lat_min_ns)
		s->lat_min_ns = lat_ns;
	if (lat_ns > s->lat_max_ns)
		s->lat_max_ns = lat_ns;
	s->hist[hist_bucket(lat_ns)]++;
}

static void stats_merge(struct worker_stats *dst, const struct worker_stats *src)
{
	/* Called after workers are joined, so no concurrent writers.
	 * Still need STAT_LOAD/STAT_ADD because fields are _Atomic. */
	STAT_ADD(dst->ios_done, STAT_LOAD(src->ios_done));
	STAT_ADD(dst->bytes_done, STAT_LOAD(src->bytes_done));
	STAT_ADD(dst->read_ios, STAT_LOAD(src->read_ios));
	STAT_ADD(dst->write_ios, STAT_LOAD(src->write_ios));
	STAT_ADD(dst->read_bytes, STAT_LOAD(src->read_bytes));
	STAT_ADD(dst->write_bytes, STAT_LOAD(src->write_bytes));
	dst->errors += src->errors;
	dst->flushes += src->flushes;
	dst->lat_sum_ns += src->lat_sum_ns;
	if (src->lat_min_ns < dst->lat_min_ns)
		dst->lat_min_ns = src->lat_min_ns;
	if (src->lat_max_ns > dst->lat_max_ns)
		dst->lat_max_ns = src->lat_max_ns;
	for (int i = 0; i < HIST_BUCKETS; i++)
		dst->hist[i] += src->hist[i];
}

/* ── CRC32 (IEEE polynomial, lookup table) ─────────────────────────── */

static uint32_t crc32_table[256];
static bool crc32_table_init;

static void crc32_init(void)
{
	if (crc32_table_init)
		return;
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c >> 1) ^ (c & 1 ? 0xEDB88320U : 0);
		crc32_table[i] = c;
	}
	crc32_table_init = true;
}

static uint32_t crc32_compute(const void *data, size_t len)
{
	const unsigned char *p = data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = (crc >> 8) ^ crc32_table[(crc ^ p[i]) & 0xFF];
	return crc ^ 0xFFFFFFFF;
}

/* ── Shared sector allocator for verify-flush mode ─────────────────── */

struct sector_alloc {
	pthread_mutex_t lock;
	uint64_t next_offset; /* next available byte offset */
	uint64_t limit;	      /* upper bound (offset + size) */
	uint64_t sector_size; /* typically = bs */
};

static void sector_alloc_init(struct sector_alloc *sa, uint64_t base, uint64_t size,
			      uint64_t sector_size)
{
	pthread_mutex_init(&sa->lock, NULL);
	sa->next_offset = base;
	sa->limit = base + size;
	sa->sector_size = sector_size;
}

/* Returns starting offset, or UINT64_MAX if exhausted */
static uint64_t sector_alloc_get(struct sector_alloc *sa, int n_sectors)
{
	uint64_t need = (uint64_t)n_sectors * sa->sector_size;
	pthread_mutex_lock(&sa->lock);
	uint64_t off = sa->next_offset;
	if (off + need > sa->limit) {
		pthread_mutex_unlock(&sa->lock);
		return UINT64_MAX;
	}
	sa->next_offset = off + need;
	pthread_mutex_unlock(&sa->lock);
	return off;
}

static void sector_alloc_destroy(struct sector_alloc *sa)
{
	pthread_mutex_destroy(&sa->lock);
}

/* ── Verify-flush: per-region record ──────────────────────────────── */

struct verify_record {
	uint64_t offset;
	uint32_t n_sectors;
	uint32_t crc;
};

/* ── SPSC ring buffer for verify-pipeline inter-thread handoff ──── */

#define PIPELINE_RING_SIZE 256 /* must be power of 2 */

struct pipeline_entry {
	uint64_t offset;
	uint32_t crc;
};

struct pipeline_ring {
	_Alignas(64) atomic_uint head; /* written by producer */
	_Alignas(64) atomic_uint tail; /* written by consumer */
	struct pipeline_entry entries[PIPELINE_RING_SIZE];
};

static void pipeline_ring_init(struct pipeline_ring *r)
{
	atomic_store_explicit(&r->head, 0, memory_order_relaxed);
	atomic_store_explicit(&r->tail, 0, memory_order_relaxed);
}

/* Push entry; spins if full. Returns false if stop_flag is set. */
static bool pipeline_ring_push(struct pipeline_ring *r, const struct pipeline_entry *e,
			       const atomic_bool *stop_flag)
{
	unsigned h = atomic_load_explicit(&r->head, memory_order_relaxed);
	for (;;) {
		unsigned t = atomic_load_explicit(&r->tail, memory_order_acquire);
		if (h - t < PIPELINE_RING_SIZE)
			break;
		if (atomic_load_explicit(stop_flag, memory_order_relaxed))
			return false;
		/* spin */
	}
	r->entries[h & (PIPELINE_RING_SIZE - 1)] = *e;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);
	return true;
}

/* Pop entry; spins if empty. Returns false if stop_flag is set and ring empty. */
static bool pipeline_ring_pop(struct pipeline_ring *r, struct pipeline_entry *e,
			      const atomic_bool *stop_flag)
{
	unsigned t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	for (;;) {
		unsigned h = atomic_load_explicit(&r->head, memory_order_acquire);
		if (h != t)
			break;
		if (atomic_load_explicit(stop_flag, memory_order_relaxed))
			return false;
		/* spin */
	}
	*e = r->entries[t & (PIPELINE_RING_SIZE - 1)];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);
	return true;
}

/* Non-blocking pop: returns true if an entry was available. */
static bool pipeline_ring_try_pop(struct pipeline_ring *r, struct pipeline_entry *e)
{
	unsigned t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	unsigned h = atomic_load_explicit(&r->head, memory_order_acquire);
	if (h == t)
		return false;
	*e = r->entries[t & (PIPELINE_RING_SIZE - 1)];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);
	return true;
}

/* ── Verify-pipeline shared context ────────────────────────────────── */

struct pipeline_ctx {
	struct sector_alloc *alloc;
	struct pipeline_ring *rings; /* array of numjobs rings */
	atomic_bool stop_flag;	     /* set when runtime expires */
	int numjobs;
};

/* ── Verify-flush worker thread ───────────────────────────────────── */

/*
 * Helper: drain exactly n_ios completions from the queue.
 * Returns number of I/O errors.
 */
static int do_io_drain(struct blkioq *q, struct blkio_completion *comps, int max_comps, int n_ios)
{
	int errs = 0;
	int outstanding = n_ios;
	while (outstanding > 0) {
		int n = blkioq_do_io(q, comps, 1, max_comps, NULL);
		if (n < 0)
			return outstanding;
		for (int i = 0; i < n; i++) {
			if (comps[i].ret != 0)
				errs++;
			outstanding--;
		}
	}
	return errs;
}

static void *verify_flush_thread(void *arg)
{
	struct worker_ctx *w = arg;
	struct bench_args *a = w->args;
	struct blkioq *q = w->queue;
	unsigned char *base = (unsigned char *)w->region.addr;
	struct sector_alloc *sa = (struct sector_alloc *)(uintptr_t)w->prng_state;
	uint64_t bs = a->bs;
	int max_sec = a->verify_max_sectors;

	int max_comps = max_sec > a->iodepth ? max_sec : a->iodepth;
	struct blkio_completion *comps = calloc(max_comps, sizeof(*comps));
	if (!comps) {
		fprintf(stderr, "verify job %d: alloc failed\n", w->job_index);
		return NULL;
	}

	size_t rec_cap = 256;
	size_t rec_count = 0;
	struct verify_record *recs = malloc(rec_cap * sizeof(*recs));
	if (!recs) {
		fprintf(stderr, "verify job %d: alloc failed\n", w->job_index);
		free(comps);
		return NULL;
	}

	uint64_t prng = 0x853c49e6748fea9bULL ^ (uint64_t)(w->job_index + 1);
	int range = a->verify_max_sectors - a->verify_min_sectors + 1;
	int total_writes = 0;

	stats_reset(&w->stats);

	/*
	 * Stage 1: Write one region at a time, drain before next.
	 */
	for (;;) {
		int n_sec = a->verify_min_sectors;
		if (range > 1)
			n_sec += (int)(xorshift64(&prng) % (uint64_t)range);

		uint64_t off = sector_alloc_get(sa, n_sec);
		if (off == UINT64_MAX)
			break;

		size_t total_bytes = (size_t)n_sec * bs;
		unsigned char *buf = base;

		for (size_t i = 0; i + 8 <= total_bytes; i += 8) {
			uint64_t val = off + i;
			memcpy(buf + i, &val, 8);
		}

		uint32_t crc = crc32_compute(buf, total_bytes);

		if (rec_count >= rec_cap) {
			rec_cap *= 2;
			struct verify_record *new_recs = realloc(recs, rec_cap * sizeof(*recs));
			if (!new_recs) {
				fprintf(stderr, "verify job %d: realloc failed\n", w->job_index);
				break;
			}
			recs = new_recs;
		}
		recs[rec_count++] = (struct verify_record){
		    .offset = off,
		    .n_sectors = (uint32_t)n_sec,
		    .crc = crc,
		};

		for (int s = 0; s < n_sec; s++)
			blkioq_write(q, off + (uint64_t)s * bs, buf + (size_t)s * bs, bs, NULL, 0);

		int errs = do_io_drain(q, comps, max_comps, n_sec);
		if (errs) {
			fprintf(stderr, "verify job %d: %d write error(s) at offset %lu\n",
				w->job_index, errs, (unsigned long)off);
			w->stats.errors += (uint64_t)errs;
		}
		total_writes += n_sec;
		STAT_ADD(w->stats.write_ios, (uint64_t)n_sec);
		STAT_ADD(w->stats.write_bytes, (uint64_t)n_sec * bs);
		STAT_ADD(w->stats.ios_done, (uint64_t)n_sec);
		STAT_ADD(w->stats.bytes_done, (uint64_t)n_sec * bs);
	}

	/*
	 * Stage 2: Flush
	 */
	blkioq_flush(q, NULL, 0);
	int ferr = do_io_drain(q, comps, max_comps, 1);
	if (ferr) {
		fprintf(stderr, "verify job %d: flush failed\n", w->job_index);
		w->stats.errors++;
	}
	w->stats.flushes++;

	/*
	 * Stage 3: Verify - re-read each region and check CRC
	 */
	int mismatches = 0;
	for (size_t r = 0; r < rec_count; r++) {
		struct verify_record *rec = &recs[r];
		size_t total_bytes = (size_t)rec->n_sectors * bs;
		unsigned char *buf = base;

		for (uint32_t s = 0; s < rec->n_sectors; s++)
			blkioq_read(q, rec->offset + (uint64_t)s * bs, buf + (size_t)s * bs, bs,
				    NULL, 0);

		int errs = do_io_drain(q, comps, max_comps, (int)rec->n_sectors);
		if (errs) {
			fprintf(stderr, "verify job %d: %d read error(s) at offset %lu\n",
				w->job_index, errs, (unsigned long)rec->offset);
			w->stats.errors += (uint64_t)errs;
		}
		STAT_ADD(w->stats.read_ios, rec->n_sectors);
		STAT_ADD(w->stats.read_bytes, (uint64_t)rec->n_sectors * bs);
		STAT_ADD(w->stats.ios_done, rec->n_sectors);
		STAT_ADD(w->stats.bytes_done, (uint64_t)rec->n_sectors * bs);

		/* Fault injection: flip one byte in first region to test detection */
		if (a->verify_inject_fault && r == 0)
			buf[0] ^= 0xFF;

		uint32_t actual_crc = crc32_compute(buf, total_bytes);
		if (actual_crc != rec->crc) {
			fprintf(stderr,
				"VERIFY FAIL: job %d, offset %lu, %u sectors: "
				"expected crc 0x%08x, got 0x%08x\n",
				w->job_index, (unsigned long)rec->offset, rec->n_sectors, rec->crc,
				actual_crc);
			mismatches++;
			w->stats.errors++;
		}
	}

	if (mismatches == 0)
		printf("verify job %d: OK - %zu regions (%d writes) verified\n", w->job_index,
		       rec_count, total_writes);
	else
		printf("verify job %d: FAILED - %d/%zu regions mismatched\n", w->job_index,
		       mismatches, rec_count);

	free(recs);
	free(comps);
	return NULL;
}

/* ── Verify-pipeline worker thread ─────────────────────────────────── */

static void *verify_pipeline_thread(void *arg)
{
	struct worker_ctx *w = arg;
	struct bench_args *a = w->args;
	struct blkioq *q = w->queue;
	unsigned char *base = (unsigned char *)w->region.addr;
	struct pipeline_ctx *pctx = (struct pipeline_ctx *)(uintptr_t)w->prng_state;
	uint64_t bs = a->bs;
	int nj = pctx->numjobs;
	int me = w->job_index;

	/* Ring I send to: next thread in circular order (or self if nj==1) */
	struct pipeline_ring *send_ring = &pctx->rings[me];
	/* Ring I receive from: previous thread */
	struct pipeline_ring *recv_ring = &pctx->rings[(me - 1 + nj) % nj];

	struct blkio_completion comp;
	stats_reset(&w->stats);

	uint64_t start_ns = now_ns();
	uint64_t end_ns = start_ns + (uint64_t)a->runtime * NS_PER_SEC;

	uint64_t total_writes = 0, total_verifies = 0, mismatches = 0;

	/* Use two buffer slots: slot 0 for writing, slot 1 for reading */
	unsigned char *wbuf = base;
	unsigned char *rbuf = base + bs;

	while (now_ns() < end_ns) {
		/* Step 1: Allocate a sector, write it */
		uint64_t off = sector_alloc_get(pctx->alloc, 1);
		if (off == UINT64_MAX)
			break;

		/* Fill with offset-seeded pattern */
		for (size_t i = 0; i + 8 <= bs; i += 8) {
			uint64_t val = off + i;
			memcpy(wbuf + i, &val, 8);
		}

		uint32_t crc = crc32_compute(wbuf, bs);

		/* Write the sector */
		blkioq_write(q, off, wbuf, bs, NULL, 0);
		int errs = do_io_drain(q, &comp, 1, 1);
		if (errs) {
			w->stats.errors++;
			continue;
		}
		total_writes++;
		STAT_INC(w->stats.write_ios);
		STAT_ADD(w->stats.write_bytes, bs);
		STAT_INC(w->stats.ios_done);
		STAT_ADD(w->stats.bytes_done, bs);

		/* Step 2: Send (offset, crc) to next thread's ring */
		struct pipeline_entry e = {.offset = off, .crc = crc};
		if (nj > 1) {
			if (!pipeline_ring_push(send_ring, &e, &pctx->stop_flag))
				break;
		}

		/* Step 3: Receive (offset, crc) from previous thread and verify */
		struct pipeline_entry recv;
		bool got;
		if (nj == 1) {
			/* Degenerate: verify our own write immediately */
			recv = e;
			got = true;
		} else {
			got = pipeline_ring_pop(recv_ring, &recv, &pctx->stop_flag);
		}

		if (!got)
			break;

		/* Read the sector */
		blkioq_read(q, recv.offset, rbuf, bs, NULL, 0);
		errs = do_io_drain(q, &comp, 1, 1);
		if (errs) {
			w->stats.errors++;
			continue;
		}
		STAT_INC(w->stats.read_ios);
		STAT_ADD(w->stats.read_bytes, bs);
		STAT_INC(w->stats.ios_done);
		STAT_ADD(w->stats.bytes_done, bs);

		/* Fault injection: flip one byte on first verify */
		if (a->verify_inject_fault && total_verifies == 0)
			rbuf[0] ^= 0xFF;

		uint32_t actual_crc = crc32_compute(rbuf, bs);
		if (actual_crc != recv.crc) {
			fprintf(stderr,
				"VERIFY FAIL: job %d, offset %lu: "
				"expected crc 0x%08x, got 0x%08x\n",
				me, (unsigned long)recv.offset, recv.crc, actual_crc);
			mismatches++;
			w->stats.errors++;
		}
		total_verifies++;
	}

	/* Signal stop so other threads don't spin forever */
	atomic_store_explicit(&pctx->stop_flag, true, memory_order_relaxed);

	/* Drain any remaining entries from recv ring (verify them) */
	if (nj > 1) {
		struct pipeline_entry recv;
		while (pipeline_ring_try_pop(recv_ring, &recv)) {
			blkioq_read(q, recv.offset, rbuf, bs, NULL, 0);
			int errs = do_io_drain(q, &comp, 1, 1);
			if (errs) {
				w->stats.errors++;
				continue;
			}
			STAT_INC(w->stats.read_ios);
			STAT_ADD(w->stats.read_bytes, bs);
			STAT_INC(w->stats.ios_done);
			STAT_ADD(w->stats.bytes_done, bs);

			uint32_t actual_crc = crc32_compute(rbuf, bs);
			if (actual_crc != recv.crc) {
				fprintf(stderr,
					"VERIFY FAIL: job %d, offset %lu: "
					"expected crc 0x%08x, got 0x%08x\n",
					me, (unsigned long)recv.offset, recv.crc, actual_crc);
				mismatches++;
				w->stats.errors++;
			}
			total_verifies++;
		}
	}

	if (mismatches == 0)
		printf("pipeline job %d: OK - %lu writes, %lu verifies\n", me,
		       (unsigned long)total_writes, (unsigned long)total_verifies);
	else
		printf("pipeline job %d: FAILED - %lu mismatches in %lu verifies\n", me,
		       (unsigned long)mismatches, (unsigned long)total_verifies);

	return NULL;
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

	if (n_blocks == 0)
		n_blocks = 1;

	if (mode_is_random(a->rw)) {
		uint64_t block = xorshift64(&w->prng_state) % n_blocks;
		return a->offset + block * a->bs;
	}
	/* sequential: wrap at aligned boundary to avoid IO extending beyond region */
	uint64_t off = a->offset + w->seq_offset;
	w->seq_offset += a->bs;
	if (w->seq_offset >= n_blocks * a->bs)
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
	int outstanding = 0;
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
		outstanding++;
	}

	w->start_ns = now_ns();
	w->ramp_end_ns = w->start_ns + (uint64_t)a->ramp_time * NS_PER_SEC;
	w->end_ns = w->start_ns + (uint64_t)(a->ramp_time + a->runtime) * NS_PER_SEC;

	/* Main I/O loop */
	for (;;) {
		int n = blkioq_do_io(q, comps, 0, depth, &zero_timeout);
		if (n < 0) {
			w->stats.errors++;
			outstanding = 0; /* can't drain after error */
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
			/* Process completions but don't requeue */
			for (int i = 0; i < n; i++) {
				struct req_slot *s = comps[i].user_data;
				if (!s) {
					outstanding--;
					continue; /* flush completion */
				}
				outstanding--;
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
			if (!s) {
				outstanding--;
				continue; /* flush completion */
			}
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
					outstanding++;
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

	/* Drain remaining in-flight IOs before returning */
	while (outstanding > 0) {
		int n = blkioq_do_io(q, comps, 1, depth, NULL);
		if (n < 0)
			break;
		outstanding -= n;
	}

	free(slots);
	free(comps);
	return NULL;
}

/* ── Forward declarations for reporter ─────────────────────────────── */

static void format_iops(double iops, char *buf, size_t len);
static bool mode_is_mixed(enum rw_mode m);
static bool mode_is_write_only(enum rw_mode m);

/* ── Progress reporter thread ──────────────────────────────────────── */

struct reporter_ctx {
	struct worker_ctx *workers;
	struct bench_args *args;
	uint64_t measure_start_ns; /* start of measurement (after ramp) */
	atomic_bool stop;
};

static void *reporter_thread(void *arg)
{
	struct reporter_ctx *r = arg;
	struct bench_args *a = r->args;
	int nj = a->numjobs;
	int interval_ms = a->eta_interval * 1000;
	bool is_mixed = mode_is_mixed(a->rw);
	uint64_t measure_start = r->measure_start_ns;

	/* Sleep through ramp period */
	while (now_ns() < measure_start) {
		if (atomic_load_explicit(&r->stop, memory_order_relaxed))
			return NULL;
		struct timespec ramp_ts = {0, 100 * 1000000L}; /* 100ms */
		nanosleep(&ramp_ts, NULL);
	}

	/* Previous snapshot for delta computation */
	uint64_t prev_ios = 0, prev_bytes = 0;
	uint64_t prev_read_bytes = 0, prev_write_bytes = 0;
	uint64_t prev_read_ios = 0, prev_write_ios = 0;

	while (!atomic_load_explicit(&r->stop, memory_order_relaxed)) {
		struct timespec ts = {
		    .tv_sec = interval_ms / 1000,
		    .tv_nsec = (long)(interval_ms % 1000) * 1000000L,
		};
		nanosleep(&ts, NULL);

		if (atomic_load_explicit(&r->stop, memory_order_relaxed))
			break;

		/* Snapshot worker counters (relaxed atomics — no torn reads) */
		uint64_t cur_ios = 0, cur_bytes = 0;
		uint64_t cur_read_bytes = 0, cur_write_bytes = 0;
		uint64_t cur_read_ios = 0, cur_write_ios = 0;
		for (int i = 0; i < nj; i++) {
			cur_ios += STAT_LOAD(r->workers[i].stats.ios_done);
			cur_bytes += STAT_LOAD(r->workers[i].stats.bytes_done);
			cur_read_bytes += STAT_LOAD(r->workers[i].stats.read_bytes);
			cur_write_bytes += STAT_LOAD(r->workers[i].stats.write_bytes);
			cur_read_ios += STAT_LOAD(r->workers[i].stats.read_ios);
			cur_write_ios += STAT_LOAD(r->workers[i].stats.write_ios);
		}

		uint64_t t = now_ns();
		double elapsed_sec = (double)(t - measure_start) / (double)NS_PER_SEC;

		/* Delta stats for this interval */
		uint64_t d_ios = cur_ios - prev_ios;
		uint64_t d_bytes = cur_bytes - prev_bytes;
		double interval_sec = (double)a->eta_interval;
		double iops = (double)d_ios / interval_sec;
		double bw_mib = (double)d_bytes / interval_sec / (1024.0 * 1024.0);

		/* Progress and ETA */
		double pct = elapsed_sec / (double)a->runtime * 100.0;
		if (pct > 100.0)
			pct = 100.0;
		double remain = (double)a->runtime - elapsed_sec;
		if (remain < 0)
			remain = 0;
		int eta_min = (int)remain / 60;
		int eta_sec = (int)remain % 60;

		char iops_str[32];
		format_iops(iops, iops_str, sizeof(iops_str));

		if (is_mixed) {
			uint64_t d_rbytes = cur_read_bytes - prev_read_bytes;
			uint64_t d_wbytes = cur_write_bytes - prev_write_bytes;
			uint64_t d_rios = cur_read_ios - prev_read_ios;
			uint64_t d_wios = cur_write_ios - prev_write_ios;
			double r_bw = (double)d_rbytes / interval_sec / (1024.0 * 1024.0);
			double w_bw = (double)d_wbytes / interval_sec / (1024.0 * 1024.0);
			char r_iops_str[32], w_iops_str[32];
			format_iops((double)d_rios / interval_sec, r_iops_str, sizeof(r_iops_str));
			format_iops((double)d_wios / interval_sec, w_iops_str, sizeof(w_iops_str));
			fprintf(stderr,
				"[%3.0fs][%5.1f%%] r=%.0fMiB/s %s IOPS, "
				"w=%.0fMiB/s %s IOPS [eta %02dm:%02ds]\n",
				elapsed_sec, pct, r_bw, r_iops_str, w_bw, w_iops_str, eta_min,
				eta_sec);
		} else {
			const char *dir = mode_is_write_only(a->rw) ? "w" : "r";
			fprintf(stderr,
				"[%3.0fs][%5.1f%%] %s=%.0fMiB/s, %s IOPS [eta %02dm:%02ds]\n",
				elapsed_sec, pct, dir, bw_mib, iops_str, eta_min, eta_sec);
		}

		prev_ios = cur_ios;
		prev_bytes = cur_bytes;
		prev_read_bytes = cur_read_bytes;
		prev_write_bytes = cur_write_bytes;
		prev_read_ios = cur_read_ios;
		prev_write_ios = cur_write_ios;
	}

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
	/*
	 * Parse utime (field 14) and stime (field 15) from /proc/self/stat.
	 * The comm field (field 2) is parenthesized and may contain spaces,
	 * so skip past the closing ')' rather than using %s which stops at
	 * the first space.  This matches the approach used by procps-ng/htop.
	 */
	char buf[1024];
	unsigned long utime = 0, stime = 0;
	int scanned = 0;
	if (fgets(buf, sizeof(buf), f)) {
		const char *cp = strrchr(buf, ')');
		if (cp)
			scanned = sscanf(cp + 2,
					 "%*c %*d %*d %*d %*d %*d %*u %*u "
					 "%*u %*u %*u %lu %lu",
					 &utime, &stime);
	}
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
	case 'k':
	case 'K':
		mult = 1024;
		end++;
		break;
	case 'm':
	case 'M':
		mult = 1024 * 1024;
		end++;
		break;
	case 'g':
	case 'G':
		mult = 1024ULL * 1024 * 1024;
		end++;
		break;
	case 't':
	case 'T':
		mult = 1024ULL * 1024 * 1024 * 1024;
		end++;
		break;
	case '\0':
		break;
	default:
		return -1;
	}
	if (*end != '\0')
		return -1;
	*out = (uint64_t)(val * (double)mult);
	return 0;
}

static enum rw_mode parse_rw(const char *str)
{
	if (!strcmp(str, "read"))
		return RW_READ;
	if (!strcmp(str, "write"))
		return RW_WRITE;
	if (!strcmp(str, "randread"))
		return RW_RANDREAD;
	if (!strcmp(str, "randwrite"))
		return RW_RANDWRITE;
	if (!strcmp(str, "readwrite") || !strcmp(str, "rw"))
		return RW_READWRITE;
	if (!strcmp(str, "randrw"))
		return RW_RANDRW;
	if (!strcmp(str, "verify-flush"))
		return RW_VERIFY_FLUSH;
	if (!strcmp(str, "verify-pipeline"))
		return RW_VERIFY_PIPELINE;
	fprintf(stderr, "error: unknown --rw mode '%s'\n", str);
	exit(1);
}

static const char *rw_name(enum rw_mode m)
{
	switch (m) {
	case RW_READ:
		return "read";
	case RW_WRITE:
		return "write";
	case RW_RANDREAD:
		return "randread";
	case RW_RANDWRITE:
		return "randwrite";
	case RW_READWRITE:
		return "readwrite";
	case RW_RANDRW:
		return "randrw";
	case RW_VERIFY_FLUSH:
		return "verify-flush";
	case RW_VERIFY_PIPELINE:
		return "verify-pipeline";
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

static void print_human_output(struct bench_args *a, struct worker_stats *total, double wall_sec,
			       struct cpu_usage *cpu_before, struct cpu_usage *cpu_after)
{
	double iops = (double)total->ios_done / wall_sec;
	double bw_bytes = (double)total->bytes_done / wall_sec;
	double bw_mib = bw_bytes / (1024.0 * 1024.0);
	double bw_mb = bw_bytes / 1e6;

	char iops_str[32];
	format_iops(iops, iops_str, sizeof(iops_str));

	char bs_str[32];
	format_size(a->bs, bs_str, sizeof(bs_str));
	printf("blkbench: rw=%s, bs=%s, iodepth=%d, numjobs=%d, runtime=%ds\n", rw_name(a->rw),
	       bs_str, a->iodepth, a->numjobs, a->runtime);

	/* Determine latency display unit based on p50 (like fio) */
	const char *lat_unit;
	double lat_div;
	uint64_t p50_ns =
	    total->ios_done > 0 ? percentile_from_hist(total->hist, total->ios_done, 50.0) : 0;
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
		printf("  read:  IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n", r_iops_str,
		       r_bw / (1024.0 * 1024.0), r_bw / 1e6);
		printf("  write: IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n", w_iops_str,
		       w_bw / (1024.0 * 1024.0), w_bw / 1e6);
	} else {
		const char *dir = has_write ? "write" : "read";
		printf("  %s: IOPS=%s, BW=%.0fMiB/s (%.0fMB/s)\n", dir, iops_str, bw_mib, bw_mb);
	}

	if (total->ios_done > 0) {
		double avg_lat = (double)total->lat_sum_ns / (double)total->ios_done / lat_div;
		double min_lat = (double)total->lat_min_ns / lat_div;
		double max_lat = (double)total->lat_max_ns / lat_div;

		printf("    lat (%s): min=%.1f, max=%.1f, avg=%.1f\n", lat_unit, min_lat, max_lat,
		       avg_lat);

		static const double pcts[] = {1, 5, 10, 50, 90, 99, 99.9, 99.99};
		static const int row_start[] = {0, 3, 6};
		static const int row_len[] = {3, 3, 2};
		printf("    lat percentiles (%s):\n", lat_unit);
		for (int r = 0; r < 3; r++) {
			printf("     |");
			for (int j = row_start[r]; j < row_start[r] + row_len[r]; j++) {
				uint64_t val_ns =
				    percentile_from_hist(total->hist, total->ios_done, pcts[j]);
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
		double wall_s =
		    (double)(cpu_after->wall_ns - cpu_before->wall_ns) / (double)NS_PER_SEC;
		double usr = (double)(cpu_after->utime_ticks - cpu_before->utime_ticks) /
			     (double)ticks_per_sec;
		double sys = (double)(cpu_after->stime_ticks - cpu_before->stime_ticks) /
			     (double)ticks_per_sec;
		if (wall_s > 0) {
			printf("  cpu: usr=%.1f%%, sys=%.1f%%\n", usr / wall_s * 100.0,
			       sys / wall_s * 100.0);
		}
	}

	printf("  ios: total=%lu, errors=%lu, flushes=%lu\n", (unsigned long)total->ios_done,
	       (unsigned long)total->errors, (unsigned long)total->flushes);
}

static void print_json_output(struct bench_args *a, struct worker_stats *total, double wall_sec,
			      struct cpu_usage *cpu_before, struct cpu_usage *cpu_after)
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
		printf("    \"mean\": %.0f,\n",
		       (double)total->lat_sum_ns / (double)total->ios_done);
		printf("    \"percentiles\": {\n");
		static const double pcts[] = {1, 5, 10, 50, 90, 99, 99.9, 99.99};
		for (int i = 0; i < 8; i++) {
			uint64_t val = percentile_from_hist(total->hist, total->ios_done, pcts[i]);
			printf("      \"p%.2f\": %lu%s\n", pcts[i], (unsigned long)val,
			       i < 7 ? "," : "");
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
		usr_pct = (double)(cpu_after->utime_ticks - cpu_before->utime_ticks) /
			  (double)ticks_per_sec / wall_s * 100.0;
		sys_pct = (double)(cpu_after->stime_ticks - cpu_before->stime_ticks) /
			  (double)ticks_per_sec / wall_s * 100.0;
	}
	printf("  \"cpu\": { \"usr\": %.2f, \"sys\": %.2f }\n", usr_pct, sys_pct);
	printf("}\n");
}

/* ── Usage ─────────────────────────────────────────────────────────── */

static void usage(void)
{
	fprintf(stderr,
		"Usage: blkbench --path PATH --rw MODE [options]\n"
		"\n"
		"Required:\n"
		"  --path PATH           Device/socket path (meaning depends on --driver)\n"
		"  --rw MODE             I/O pattern: read, write, randread, randwrite,\n"
		"                        readwrite, randrw, verify-flush, verify-pipeline\n"
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
		"Verify options (for --rw verify-flush):\n"
		"  --verify-sectors M:N  Sectors per write region (default: 1:16)\n"
		"\n"
		"libblkio options:\n"
		"  --driver NAME         libblkio driver (default: virtio-blk-vhost-user)\n"
		"  --direct 0|1          Use direct I/O, bypass page cache (default: 1)\n"
		"\n"
		"Output options:\n"
		"  --output-format FMT   Output format: normal, json (default: normal)\n"
		"  --eta-interval SEC    Progress line interval; 0=disabled (default: 2)\n"
		"\n"
		"  --help                Show this help\n"
		"  --version             Show version\n");
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
	    .queue_size = 0, /* set to iodepth after arg parsing */
	    .json_output = false,
	    .direct = 1,
	    .verify_min_sectors = 1,
	    .verify_max_sectors = 16,
	    .verify_inject_fault = false,
	    .eta_interval = 2,
	};
	bool rw_set = false;

	static struct option long_options[] = {
	    {"path", required_argument, 0, 'p'},
	    {"rw", required_argument, 0, 'r'},
	    {"bs", required_argument, 0, 'b'},
	    {"iodepth", required_argument, 0, 'd'},
	    {"numjobs", required_argument, 0, 'j'},
	    {"runtime", required_argument, 0, 't'},
	    {"size", required_argument, 0, 's'},
	    {"offset", required_argument, 0, 'o'},
	    {"rwmixread", required_argument, 0, 'm'},
	    {"ramp_time", required_argument, 0, 'R'},
	    {"sync", required_argument, 0, 'S'},
	    {"driver", required_argument, 0, 'D'},
	    /* --queue-size removed: uses iodepth as queue size */
	    {"output-format", required_argument, 0, 'F'},
	    {"verify-sectors", required_argument, 0, 'E'},
	    {"direct", required_argument, 0, 'O'},
	    {"eta-interval", required_argument, 0, 'e'},
	    {"verify-inject-fault", no_argument, 0, 'I'},
	    {"help", no_argument, 0, 'h'},
	    {"version", no_argument, 0, 'V'},
	    {0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
		switch (opt) {
		case 'p':
			args.path = optarg;
			break;
		case 'r':
			args.rw = parse_rw(optarg);
			rw_set = true;
			break;
		case 'b':
			if (parse_size(optarg, &args.bs) < 0) {
				fprintf(stderr, "error: invalid --bs '%s'\n", optarg);
				return 1;
			}
			break;
		case 'd':
			args.iodepth = atoi(optarg);
			break;
		case 'j':
			args.numjobs = atoi(optarg);
			break;
		case 't':
			args.runtime = atoi(optarg);
			break;
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
		case 'm':
			args.rwmixread = atoi(optarg);
			break;
		case 'R':
			args.ramp_time = atoi(optarg);
			break;
		case 'S':
			args.sync_n = atoi(optarg);
			break;
		case 'D':
			args.driver = optarg;
			break;
		/* 'Q' removed: queue-size derived from iodepth */
		case 'F':
			if (!strcmp(optarg, "json"))
				args.json_output = true;
			else if (strcmp(optarg, "normal")) {
				fprintf(stderr, "error: unknown --output-format '%s'\n", optarg);
				return 1;
			}
			break;
		case 'E': {
			/* --verify-sectors=MIN:MAX */
			char *colon = strchr(optarg, ':');
			if (!colon) {
				fprintf(stderr, "error: --verify-sectors expects MIN:MAX\n");
				return 1;
			}
			args.verify_min_sectors = atoi(optarg);
			args.verify_max_sectors = atoi(colon + 1);
			if (args.verify_min_sectors < 1 ||
			    args.verify_max_sectors < args.verify_min_sectors) {
				fprintf(stderr, "error: --verify-sectors: need 1 <= MIN <= MAX\n");
				return 1;
			}
			break;
		}
		case 'O':
			args.direct = atoi(optarg);
			break;
		case 'e':
			args.eta_interval = atoi(optarg);
			break;
		case 'I':
			args.verify_inject_fault = true;
			break;
		case 'h':
			usage();
			return 0;
		case 'V':
			printf("blkbench %s\n", VERSION);
			return 0;
		default:
			usage();
			return 1;
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

	/* Use iodepth as queue size — no need for a separate knob */
	args.queue_size = args.iodepth;

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
	if (args.runtime < 1 && args.rw != RW_VERIFY_FLUSH && args.rw != RW_VERIFY_PIPELINE) {
		fprintf(stderr, "error: --runtime must be >= 1\n");
		return 1;
	}
	if (args.rwmixread < 0 || args.rwmixread > 100) {
		fprintf(stderr, "error: --rwmixread must be 0-100\n");
		return 1;
	}
	if (args.ramp_time < 0) {
		fprintf(stderr, "error: --ramp_time must be >= 0\n");
		return 1;
	}
	if (args.sync_n < 0) {
		fprintf(stderr, "error: --sync must be >= 0\n");
		return 1;
	}
	if (args.eta_interval < 0) {
		fprintf(stderr, "error: --eta-interval must be >= 0\n");
		return 1;
	}

	/* ── Create and connect blkio instance ── */
	struct blkio *b = NULL;
	int ret;

	ret = blkio_create(args.driver, &b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_create(%s): %s\n", args.driver,
			blkio_get_error_msg());
		return 1;
	}

	ret = blkio_set_str(b, "path", args.path);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_set_str(path): %s\n", blkio_get_error_msg());
		blkio_destroy(&b);
		return 1;
	}

	if (args.direct >= 0 && !strcmp(args.driver, "io_uring")) {
		ret = blkio_set_bool(b, "direct", args.direct != 0);
		if (ret < 0) {
			fprintf(stderr, "error: blkio_set_bool(direct): %s\n",
				blkio_get_error_msg());
			blkio_destroy(&b);
			return 1;
		}
	}

	ret = blkio_connect(b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_connect: %s\n", blkio_get_error_msg());
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
		if (args.offset >= capacity) {
			fprintf(stderr, "error: --offset %lu exceeds device capacity %lu\n",
				(unsigned long)args.offset, (unsigned long)capacity);
			blkio_destroy(&b);
			return 1;
		}
		args.size = capacity - args.offset;
	} else if (capacity > 0 && args.offset + args.size > capacity) {
		fprintf(stderr, "error: --offset + --size (%lu) exceeds device capacity (%lu)\n",
			(unsigned long)(args.offset + args.size), (unsigned long)capacity);
		blkio_destroy(&b);
		return 1;
	}

	/* Validate numjobs against backend's max-queues */
	int max_queues = 0;
	if (blkio_get_int(b, "max-queues", &max_queues) == 0 && max_queues > 0 &&
	    args.numjobs > max_queues) {
		fprintf(stderr, "error: --numjobs %d exceeds backend's maximum queue count of %d\n",
			args.numjobs, max_queues);
		blkio_destroy(&b);
		return 1;
	}

	/* Set queue properties */
	blkio_set_int(b, "num-queues", args.numjobs);

	/* Queue size = iodepth. This is the natural minimum and avoids
	 * negotiation issues with backends that have small queue limits. */
	blkio_set_int(b, "queue-size", args.queue_size);

	ret = blkio_start(b);
	if (ret < 0) {
		fprintf(stderr, "error: blkio_start: %s\n", blkio_get_error_msg());
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

	bool is_verify_flush = (args.rw == RW_VERIFY_FLUSH);
	bool is_verify_pipeline = (args.rw == RW_VERIFY_PIPELINE);
	bool is_verify = is_verify_flush || is_verify_pipeline;
	size_t region_size;
	struct sector_alloc sa;
	struct pipeline_ctx pctx = {0};

	/* 16 GiB per-worker memory region limit */
	const size_t max_region = (size_t)16 * 1024 * 1024 * 1024;

	if (is_verify_flush) {
		crc32_init();
		/* Each slot needs verify_max_sectors * bs for multi-sector regions */
		size_t slots = (size_t)args.iodepth * (size_t)args.verify_max_sectors;
		if (slots / (size_t)args.iodepth != (size_t)args.verify_max_sectors ||
		    slots > SIZE_MAX / args.bs) {
			fprintf(stderr, "error: iodepth * verify_max_sectors * bs overflows\n");
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}
		region_size = slots * args.bs;
		sector_alloc_init(&sa, args.offset, args.size, args.bs);
	} else if (is_verify_pipeline) {
		crc32_init();
		/* Need 2 buffer slots per worker: one for write, one for read */
		region_size = 2 * args.bs;
		sector_alloc_init(&sa, args.offset, args.size, args.bs);
		pctx.alloc = &sa;
		pctx.numjobs = args.numjobs;
		atomic_store(&pctx.stop_flag, false);
		pctx.rings = calloc(args.numjobs, sizeof(struct pipeline_ring));
		if (!pctx.rings) {
			fprintf(stderr, "error: alloc pipeline rings failed\n");
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}
		for (int i = 0; i < args.numjobs; i++)
			pipeline_ring_init(&pctx.rings[i]);
	} else {
		if ((size_t)args.iodepth > SIZE_MAX / args.bs) {
			fprintf(stderr, "error: iodepth * bs overflows\n");
			free(workers);
			free(threads);
			blkio_destroy(&b);
			return 1;
		}
		region_size = (size_t)args.iodepth * args.bs;
	}

	if (region_size > max_region) {
		fprintf(
		    stderr,
		    "error: memory region per worker = %zu bytes (%.1f GiB) exceeds 16 GiB limit\n",
		    region_size, (double)region_size / (1024.0 * 1024.0 * 1024.0));
		free(workers);
		free(threads);
		blkio_destroy(&b);
		return 1;
	}

	for (int i = 0; i < args.numjobs; i++) {
		workers[i].job_index = i;
		workers[i].args = &args;
		if (is_verify_flush)
			workers[i].prng_state = (uint64_t)(uintptr_t)&sa;
		else if (is_verify_pipeline)
			workers[i].prng_state = (uint64_t)(uintptr_t)&pctx;
		else
			workers[i].prng_state = 0x853c49e6748fea9bULL ^ (uint64_t)(i + 1);
		workers[i].seq_offset = 0;
		workers[i].write_counter = 0;

		ret = blkio_alloc_mem_region(b, &workers[i].region, region_size);
		if (ret < 0) {
			fprintf(stderr, "error: blkio_alloc_mem_region (job %d): %s\n", i,
				blkio_get_error_msg());
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
			fprintf(stderr, "error: blkio_map_mem_region (job %d): %s\n", i,
				blkio_get_error_msg());
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

	void *(*thread_fn)(void *) = is_verify_flush	  ? verify_flush_thread
				     : is_verify_pipeline ? verify_pipeline_thread
							  : worker_thread;
	uint64_t bench_start_ns = now_ns();
	for (int i = 0; i < args.numjobs; i++) {
		ret = pthread_create(&threads[i], NULL, thread_fn, &workers[i]);
		if (ret) {
			fprintf(stderr, "error: pthread_create (job %d): %s\n", i, strerror(ret));
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

	/* ── Start progress reporter (non-verify modes, eta_interval > 0) ── */
	struct reporter_ctx rctx = {0};
	pthread_t reporter_tid;
	bool reporter_running = false;
	if (!is_verify && args.eta_interval > 0) {
		rctx.workers = workers;
		rctx.args = &args;
		rctx.measure_start_ns = bench_start_ns + (uint64_t)args.ramp_time * NS_PER_SEC;
		atomic_store_explicit(&rctx.stop, false, memory_order_relaxed);
		ret = pthread_create(&reporter_tid, NULL, reporter_thread, &rctx);
		if (ret == 0)
			reporter_running = true;
	}

	for (int i = 0; i < args.numjobs; i++)
		pthread_join(threads[i], NULL);

	/* Stop reporter before aggregating results */
	if (reporter_running) {
		atomic_store_explicit(&rctx.stop, true, memory_order_relaxed);
		pthread_join(reporter_tid, NULL);
	}

	uint64_t bench_end_ns = now_ns();

	read_cpu_usage(&cpu_after);

	/* ── Aggregate stats ── */
	struct worker_stats total;
	stats_reset(&total);
	for (int i = 0; i < args.numjobs; i++)
		stats_merge(&total, &workers[i].stats);

	if (is_verify_flush) {
		printf("verify-flush: %lu writes, %lu reads, %lu errors, %lu flushes\n",
		       (unsigned long)total.write_ios, (unsigned long)total.read_ios,
		       (unsigned long)total.errors, (unsigned long)total.flushes);
	} else if (is_verify_pipeline) {
		printf("verify-pipeline: %lu writes, %lu reads, %lu errors\n",
		       (unsigned long)total.write_ios, (unsigned long)total.read_ios,
		       (unsigned long)total.errors);
	} else {
		double wall_sec = (double)(bench_end_ns - bench_start_ns) / (double)NS_PER_SEC -
				  (double)args.ramp_time;
		if (wall_sec < 0.001)
			wall_sec = 0.001;

		/* ── Print results ── */
		if (args.json_output)
			print_json_output(&args, &total, wall_sec, &cpu_before, &cpu_after);
		else
			print_human_output(&args, &total, wall_sec, &cpu_before, &cpu_after);
	}

	/* ── Cleanup ── */
	for (int i = 0; i < args.numjobs; i++) {
		blkio_unmap_mem_region(b, &workers[i].region);
		blkio_free_mem_region(b, &workers[i].region);
	}
	if (is_verify)
		sector_alloc_destroy(&sa);
	if (is_verify_pipeline)
		free(pctx.rings);
	free(workers);
	free(threads);
	blkio_destroy(&b);

	return (is_verify && total.errors) ? 1 : 0;
}
