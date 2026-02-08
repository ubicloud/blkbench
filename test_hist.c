/*
 * test_hist.c - Unit test for latency histogram and percentile logic
 *
 * Verifies hist_bucket(), hist_bucket_upper_ns(), percentile_from_hist()
 * by feeding known latency values and checking derived percentiles.
 *
 * Build: gcc -O2 -Wall -o test_hist test_hist.c -lm
 * Run:   ./test_hist
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HIST_BUCKETS 32
#define NS_PER_US    1000ULL
#define NS_PER_MS    1000000ULL
#define NS_PER_SEC   1000000000ULL

/* ── Copy of histogram functions from lblk-bench.c ─────────────── */

static int hist_bucket(uint64_t lat_ns)
{
	if (lat_ns < NS_PER_US)
		return 0;
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

/* ── Test infrastructure ──────────────────────────────────────── */

static int tests_run = 0;
static int tests_passed = 0;

#define CHECK(cond, fmt, ...)                                                                      \
	do {                                                                                       \
		tests_run++;                                                                       \
		if (cond) {                                                                        \
			tests_passed++;                                                            \
		} else {                                                                           \
			printf("FAIL: " fmt "\n", ##__VA_ARGS__);                                  \
		}                                                                                  \
	} while (0)

/* ── Tests ────────────────────────────────────────────────────── */

static void test_bucket_boundaries(void)
{
	printf("== test_bucket_boundaries ==\n");

	/* Sub-microsecond -> bucket 0 */
	CHECK(hist_bucket(0) == 0, "0ns -> bucket 0 (got %d)", hist_bucket(0));
	CHECK(hist_bucket(500) == 0, "500ns -> bucket 0 (got %d)", hist_bucket(500));
	CHECK(hist_bucket(999) == 0, "999ns -> bucket 0 (got %d)", hist_bucket(999));

	/* 1us = 1000ns -> bucket 1 ([1us, 2us)) */
	CHECK(hist_bucket(1000) == 1, "1000ns -> bucket 1 (got %d)", hist_bucket(1000));
	CHECK(hist_bucket(1500) == 1, "1500ns -> bucket 1 (got %d)", hist_bucket(1500));
	CHECK(hist_bucket(1999) == 1, "1999ns -> bucket 1 (got %d)", hist_bucket(1999));

	/* 2us = 2000ns -> bucket 2 ([2us, 4us)) */
	CHECK(hist_bucket(2000) == 2, "2000ns -> bucket 2 (got %d)", hist_bucket(2000));
	CHECK(hist_bucket(3999) == 2, "3999ns -> bucket 2 (got %d)", hist_bucket(3999));

	/* 4us -> bucket 3 ([4us, 8us)) */
	CHECK(hist_bucket(4000) == 3, "4000ns -> bucket 3 (got %d)", hist_bucket(4000));
	CHECK(hist_bucket(7999) == 3, "7999ns -> bucket 3 (got %d)", hist_bucket(7999));

	/* 8us -> bucket 4 ([8us, 16us)) */
	CHECK(hist_bucket(8000) == 4, "8000ns -> bucket 4 (got %d)", hist_bucket(8000));

	/* 1ms = 1000us -> bucket 11 ([512us, 1024us)... let's check) */
	/* 1ms = 1,000,000 ns. bucket 1 threshold starts at 2us, each bucket doubles.
	   bucket 1: [1us, 2us), bucket 2: [2us, 4us), ..., bucket k: [2^(k-1)us, 2^k us)
	   1000us: 2^(k-1) <= 1000 < 2^k => k=10 since 2^10=1024, 2^9=512
	   So 1ms should be in bucket 11 (threshold at 2^11 * 1000 = 2048us).
	   Wait, let me re-derive. threshold starts at 2*NS_PER_US=2000ns at b=1.
	   b=1, threshold=2000 (2us)
	   b=2, threshold=4000 (4us)
	   b=3, threshold=8000 (8us)
	   ...
	   b=k, threshold=2000<<(k-1) = 2^k * 1000 = 2^k us
	   1ms = 1000us = 1,000,000ns. We need threshold > 1,000,000.
	   2^k * 1000 > 1,000,000 => 2^k > 1000 => k >= 10 (2^10=1024)
	   So bucket 10: threshold was 2^10*1000=1,024,000. 1,000,000 < 1,024,000. ✓
	*/
	CHECK(hist_bucket(1000000) == 10, "1ms -> bucket 10 (got %d)", hist_bucket(1000000));

	/* 1s = 1,000,000,000 ns.
	   2^k * 1000 > 1,000,000,000 => 2^k > 1,000,000 => k >= 20 (2^20=1,048,576)
	   So bucket 20.
	*/
	CHECK(hist_bucket(NS_PER_SEC) == 20, "1s -> bucket 20 (got %d)", hist_bucket(NS_PER_SEC));

	/* Very large values should cap at HIST_BUCKETS-1 = 31 */
	CHECK(hist_bucket(UINT64_MAX) == HIST_BUCKETS - 1, "UINT64_MAX -> bucket 31 (got %d)",
	      hist_bucket(UINT64_MAX));
}

static void test_bucket_upper_bounds(void)
{
	printf("== test_bucket_upper_bounds ==\n");

	CHECK(hist_bucket_upper_ns(0) == 1000, "bucket 0 upper = 1us (got %lu)",
	      (unsigned long)hist_bucket_upper_ns(0));
	CHECK(hist_bucket_upper_ns(1) == 2000, "bucket 1 upper = 2us (got %lu)",
	      (unsigned long)hist_bucket_upper_ns(1));
	CHECK(hist_bucket_upper_ns(2) == 4000, "bucket 2 upper = 4us (got %lu)",
	      (unsigned long)hist_bucket_upper_ns(2));
	CHECK(hist_bucket_upper_ns(10) == 1024000, "bucket 10 upper = 1024us (got %lu)",
	      (unsigned long)hist_bucket_upper_ns(10));
}

static void test_percentiles_uniform(void)
{
	printf("== test_percentiles_uniform ==\n");

	/* 100 samples, all in bucket 2 (2-4us range) */
	uint64_t hist[HIST_BUCKETS] = {0};
	hist[2] = 100;
	uint64_t total = 100;

	/* All percentiles should return bucket 2 upper = 4us = 4000ns */
	CHECK(percentile_from_hist(hist, total, 1.0) == 4000, "p1 = 4000 (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 1.0));
	CHECK(percentile_from_hist(hist, total, 50.0) == 4000, "p50 = 4000 (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 50.0));
	CHECK(percentile_from_hist(hist, total, 99.0) == 4000, "p99 = 4000 (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 99.0));
}

static void test_percentiles_bimodal(void)
{
	printf("== test_percentiles_bimodal ==\n");

	/* 50 samples at <1us (bucket 0), 50 samples at 1ms range (bucket 10) */
	uint64_t hist[HIST_BUCKETS] = {0};
	hist[0] = 50;
	hist[10] = 50;
	uint64_t total = 100;

	/* p1 -> target = ceil(1) = 1 -> bucket 0 -> upper = 1000ns */
	CHECK(percentile_from_hist(hist, total, 1.0) == 1000, "p1 = 1000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 1.0));

	/* p50 -> target = ceil(50) = 50 -> cumulative at bucket 0 = 50 >= 50 -> bucket 0 */
	CHECK(percentile_from_hist(hist, total, 50.0) == 1000, "p50 = 1000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 50.0));

	/* p51 -> target = ceil(51) = 51 -> need bucket 10 */
	CHECK(percentile_from_hist(hist, total, 51.0) == 1024000, "p51 = 1024000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 51.0));

	/* p99 -> target = ceil(99) = 99 -> bucket 10 */
	CHECK(percentile_from_hist(hist, total, 99.0) == 1024000, "p99 = 1024000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 99.0));
}

static void test_percentiles_spread(void)
{
	printf("== test_percentiles_spread ==\n");

	/* 10 samples per bucket 0..9 = 100 total */
	uint64_t hist[HIST_BUCKETS] = {0};
	for (int i = 0; i < 10; i++)
		hist[i] = 10;
	uint64_t total = 100;

	/* p10 -> target=10 -> cumulative at bucket 0 = 10 >= 10 -> bucket 0 upper = 1000 */
	CHECK(percentile_from_hist(hist, total, 10.0) == 1000, "p10 = 1000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 10.0));

	/* p11 -> target=11 -> cumulative at bucket 0 = 10, bucket 1 = 20 >= 11 -> bucket 1 upper =
	 * 2000 */
	CHECK(percentile_from_hist(hist, total, 11.0) == 2000, "p11 = 2000ns (got %lu)",
	      (unsigned long)percentile_from_hist(hist, total, 11.0));

	/* p50 -> target=50 -> cumulative at bucket 4 = 50 >= 50 -> bucket 4 upper = 16000 */
	CHECK(percentile_from_hist(hist, total, 50.0) == (NS_PER_US << 4),
	      "p50 = 16000ns (got %lu)", (unsigned long)percentile_from_hist(hist, total, 50.0));

	/* p90 -> target=90 -> cumulative at bucket 8 = 90 >= 90 -> bucket 8 upper = 256000 */
	CHECK(percentile_from_hist(hist, total, 90.0) == (NS_PER_US << 8),
	      "p90 = 256000ns (got %lu)", (unsigned long)percentile_from_hist(hist, total, 90.0));

	/* p91 -> target=91 -> cumulative at bucket 9 = 100 >= 91 -> bucket 9 upper = 512000 */
	CHECK(percentile_from_hist(hist, total, 91.0) == (NS_PER_US << 9),
	      "p91 = 512000ns (got %lu)", (unsigned long)percentile_from_hist(hist, total, 91.0));
}

static void test_stats_record_and_hist(void)
{
	printf("== test_stats_record_and_hist ==\n");

	/* Simulate what the I/O loop does: call stats_record and check histogram */
	uint64_t lat_min = UINT64_MAX, lat_max = 0, lat_sum = 0;
	uint64_t ios_done = 0;
	uint64_t hist[HIST_BUCKETS] = {0};

	/* Feed 1000 latencies: 500 at 5us, 300 at 50us, 200 at 500us */
	uint64_t values[] = {5000, 50000, 500000};
	int counts[] = {500, 300, 200};

	for (int v = 0; v < 3; v++) {
		for (int i = 0; i < counts[v]; i++) {
			uint64_t lat = values[v];
			ios_done++;
			lat_sum += lat;
			if (lat < lat_min)
				lat_min = lat;
			if (lat > lat_max)
				lat_max = lat;
			hist[hist_bucket(lat)]++;
		}
	}

	CHECK(ios_done == 1000, "ios = 1000 (got %lu)", (unsigned long)ios_done);
	CHECK(lat_min == 5000, "min = 5000 (got %lu)", (unsigned long)lat_min);
	CHECK(lat_max == 500000, "max = 500000 (got %lu)", (unsigned long)lat_max);

	double avg = (double)lat_sum / (double)ios_done;
	double expected_avg = (500.0 * 5000 + 300.0 * 50000 + 200.0 * 500000) / 1000.0;
	CHECK(fabs(avg - expected_avg) < 1.0, "avg = %.1f (expected %.1f)", avg, expected_avg);

	/* 5us -> bucket 3 ([4us,8us)), 50us -> bucket 6 ([32us,64us)), 500us -> bucket 9
	 * ([256us,512us)) */
	CHECK(hist[hist_bucket(5000)] == 500, "5us bucket count=500 (got %lu)",
	      (unsigned long)hist[hist_bucket(5000)]);
	CHECK(hist[hist_bucket(50000)] == 300, "50us bucket count=300 (got %lu)",
	      (unsigned long)hist[hist_bucket(50000)]);
	CHECK(hist[hist_bucket(500000)] == 200, "500us bucket count=200 (got %lu)",
	      (unsigned long)hist[hist_bucket(500000)]);

	/* p50: target=500. cumulative at bucket 3 = 500 >= 500. -> bucket 3 upper = 8000ns = 8us */
	uint64_t p50 = percentile_from_hist(hist, ios_done, 50.0);
	CHECK(p50 == 8000, "p50 = 8us (got %luus)", (unsigned long)(p50 / 1000));

	/* p80: target=800. cumulative at bucket 3=500, bucket 6=500+300=800 >= 800.
	   -> bucket 6 upper = 64us = 64000ns */
	uint64_t p80 = percentile_from_hist(hist, ios_done, 80.0);
	CHECK(p80 == 64000, "p80 = 64us (got %luus)", (unsigned long)(p80 / 1000));

	/* p99: target=990. cumulative at bucket 6 = 800 < 990. bucket 9 = 800+200=1000 >= 990.
	   -> bucket 9 upper = 512000ns = 512us */
	uint64_t p99 = percentile_from_hist(hist, ios_done, 99.0);
	CHECK(p99 == 512000, "p99 = 512us (got %luus)", (unsigned long)(p99 / 1000));
}

int main(void)
{
	test_bucket_boundaries();
	test_bucket_upper_bounds();
	test_percentiles_uniform();
	test_percentiles_bimodal();
	test_percentiles_spread();
	test_stats_record_and_hist();

	printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
