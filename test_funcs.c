/*
 * test_funcs.c - Unit tests for pure utility functions from lblk-bench.c
 *
 * Tests: parse_size(), xorshift64(), format_size(), format_iops()
 *
 * Build: gcc -O2 -Wall -o test_funcs test_funcs.c -lm
 * Run:   ./test_funcs
 */

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Copy of functions from lblk-bench.c ───────────────────────────── */

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

static uint64_t xorshift64(uint64_t *state)
{
	uint64_t x = *state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

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

/* ── Test infrastructure ───────────────────────────────────────────── */

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

/* ── parse_size tests ──────────────────────────────────────────────── */

static void test_parse_size(void)
{
	printf("== test_parse_size ==\n");
	uint64_t out;

	/* Plain numbers */
	CHECK(parse_size("4096", &out) == 0 && out == 4096, "4096 -> %lu", (unsigned long)out);
	CHECK(parse_size("0", &out) == 0 && out == 0, "0 -> %lu", (unsigned long)out);
	CHECK(parse_size("1", &out) == 0 && out == 1, "1 -> %lu", (unsigned long)out);

	/* k/K suffix */
	CHECK(parse_size("4k", &out) == 0 && out == 4096, "4k -> %lu", (unsigned long)out);
	CHECK(parse_size("4K", &out) == 0 && out == 4096, "4K -> %lu", (unsigned long)out);
	CHECK(parse_size("1k", &out) == 0 && out == 1024, "1k -> %lu", (unsigned long)out);
	CHECK(parse_size("64k", &out) == 0 && out == 65536, "64k -> %lu", (unsigned long)out);

	/* m/M suffix */
	CHECK(parse_size("1m", &out) == 0 && out == 1048576, "1m -> %lu", (unsigned long)out);
	CHECK(parse_size("64M", &out) == 0 && out == 67108864, "64M -> %lu", (unsigned long)out);

	/* g/G suffix */
	CHECK(parse_size("1g", &out) == 0 && out == 1073741824ULL, "1g -> %lu", (unsigned long)out);
	CHECK(parse_size("2G", &out) == 0 && out == 2147483648ULL, "2G -> %lu", (unsigned long)out);

	/* t/T suffix */
	CHECK(parse_size("1t", &out) == 0 && out == 1099511627776ULL, "1t -> %lu",
	      (unsigned long)out);

	/* Fractional with suffix */
	CHECK(parse_size("1.5k", &out) == 0 && out == 1536, "1.5k -> %lu", (unsigned long)out);
	CHECK(parse_size("0.5m", &out) == 0 && out == 524288, "0.5m -> %lu", (unsigned long)out);

	/* Error cases */
	CHECK(parse_size("", &out) == -1, "empty string rejected");
	CHECK(parse_size("abc", &out) == -1, "non-numeric rejected");
	CHECK(parse_size("-1", &out) == -1, "negative rejected");
	CHECK(parse_size("4x", &out) == -1, "unknown suffix rejected");
	CHECK(parse_size("4kb", &out) == -1, "trailing chars rejected");
}

/* ── xorshift64 tests ──────────────────────────────────────────────── */

static void test_xorshift64(void)
{
	printf("== test_xorshift64 ==\n");

	/* Deterministic: same seed -> same sequence */
	uint64_t s1 = 0x853c49e6748fea9bULL;
	uint64_t s2 = 0x853c49e6748fea9bULL;
	uint64_t a = xorshift64(&s1);
	uint64_t b = xorshift64(&s2);
	CHECK(a == b, "deterministic: same seed same result (a=%lu b=%lu)", (unsigned long)a,
	      (unsigned long)b);

	/* Non-zero: output should never be 0 for reasonable seeds */
	uint64_t state = 1;
	int any_zero = 0;
	for (int i = 0; i < 10000; i++) {
		if (xorshift64(&state) == 0)
			any_zero = 1;
	}
	CHECK(!any_zero, "no zero output in 10000 iterations");

	/* State changes after call */
	uint64_t s3 = 42;
	uint64_t old_state = s3;
	xorshift64(&s3);
	CHECK(s3 != old_state, "state changed after call");

	/* Distribution: check all 64 bits are exercised (no stuck bits) */
	uint64_t state2 = 0xdeadbeefcafebabeULL;
	uint64_t or_all = 0, and_all = ~0ULL;
	for (int i = 0; i < 10000; i++) {
		uint64_t v = xorshift64(&state2);
		or_all |= v;
		and_all &= v;
	}
	CHECK(or_all == ~0ULL, "all bits set at least once (or=%lx)", (unsigned long)or_all);
	CHECK(and_all == 0ULL, "all bits cleared at least once (and=%lx)", (unsigned long)and_all);
}

/* ── format_size tests ─────────────────────────────────────────────── */

static void test_format_size(void)
{
	printf("== test_format_size ==\n");
	char buf[32];

	format_size(4096, buf, sizeof(buf));
	CHECK(strcmp(buf, "4k") == 0, "4096 -> '%s'", buf);

	format_size(1048576, buf, sizeof(buf));
	CHECK(strcmp(buf, "1m") == 0, "1048576 -> '%s'", buf);

	format_size(1073741824, buf, sizeof(buf));
	CHECK(strcmp(buf, "1g") == 0, "1073741824 -> '%s'", buf);

	format_size(512, buf, sizeof(buf));
	CHECK(strcmp(buf, "512") == 0, "512 -> '%s'", buf);

	format_size(1024, buf, sizeof(buf));
	CHECK(strcmp(buf, "1k") == 0, "1024 -> '%s'", buf);

	format_size(3000, buf, sizeof(buf));
	CHECK(strcmp(buf, "3000") == 0, "3000 (not aligned) -> '%s'", buf);

	format_size(65536, buf, sizeof(buf));
	CHECK(strcmp(buf, "64k") == 0, "65536 -> '%s'", buf);
}

/* ── format_iops tests ─────────────────────────────────────────────── */

static void test_format_iops(void)
{
	printf("== test_format_iops ==\n");
	char buf[32];

	format_iops(500.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "500") == 0, "500 -> '%s'", buf);

	format_iops(1500.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "1.50k") == 0, "1500 -> '%s'", buf);

	format_iops(50000.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "50.0k") == 0, "50000 -> '%s'", buf);

	format_iops(320000.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "320.0k") == 0, "320000 -> '%s'", buf);

	format_iops(1500000.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "1.5M") == 0, "1500000 -> '%s'", buf);

	format_iops(4900000.0, buf, sizeof(buf));
	CHECK(strcmp(buf, "4.9M") == 0, "4900000 -> '%s'", buf);
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(void)
{
	test_parse_size();
	test_xorshift64();
	test_format_size();
	test_format_iops();

	printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
