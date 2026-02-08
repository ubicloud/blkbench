/*
 * poc.c - libblkio vhost-user-blk proof of concept
 *
 * Connects to a running ubiblk vhost-backend via libblkio, writes a known
 * pattern, reads it back to verify correctness, then benchmarks sequential
 * 4K reads for throughput.
 *
 * Usage: ./poc [socket_path]
 *   socket_path defaults to /tmp/vhost.sock
 */

#include <blkio.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE      4096
#define BENCH_ITERS     1000
#define MAGIC_BYTE      0xA5

static void check(int ret, const char *msg)
{
    if (ret < 0) {
        fprintf(stderr, "FAIL: %s: %s (%s)\n",
                msg, strerror(-ret), blkio_get_error_msg());
        exit(1);
    }
}

static double elapsed_sec(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec)
         + (end->tv_nsec - start->tv_nsec) / 1e9;
}

int main(int argc, char **argv)
{
    const char *socket_path = argc > 1 ? argv[1] : "/tmp/vhost.sock";
    struct blkio *b = NULL;
    struct blkio_mem_region region = {0};
    struct blkio_completion comp;
    int ret;

    printf("poc: libblkio vhost-user-blk proof of concept\n");
    printf("poc: socket = %s\n\n", socket_path);

    /* --- Create and connect --- */
    check(blkio_create("virtio-blk-vhost-user", &b),
          "blkio_create");
    check(blkio_set_str(b, "path", socket_path),
          "blkio_set_str(path)");
    check(blkio_connect(b),
          "blkio_connect");

    /* Query device capacity */
    uint64_t capacity = 0;
    check(blkio_get_uint64(b, "capacity", &capacity),
          "blkio_get_uint64(capacity)");
    printf("poc: device capacity = %lu bytes (%.1f MiB)\n",
           (unsigned long)capacity, capacity / (1024.0 * 1024.0));

    /* --- Configure and start --- */
    check(blkio_set_int(b, "num-queues", 1),
          "blkio_set_int(num-queues)");
    check(blkio_set_int(b, "queue-size", 64),
          "blkio_set_int(queue-size)");
    check(blkio_start(b),
          "blkio_start");

    /* --- Allocate and map memory --- */
    check(blkio_alloc_mem_region(b, &region, BLOCK_SIZE),
          "blkio_alloc_mem_region");
    check(blkio_map_mem_region(b, &region),
          "blkio_map_mem_region");

    struct blkioq *q = blkio_get_queue(b, 0);
    if (!q) {
        fprintf(stderr, "FAIL: blkio_get_queue returned NULL\n");
        exit(1);
    }

    unsigned char *buf = (unsigned char *)region.addr;

    /* --- Write a known pattern --- */
    printf("\npoc: writing %d bytes of 0x%02X to offset 0...\n",
           BLOCK_SIZE, MAGIC_BYTE);
    memset(buf, MAGIC_BYTE, BLOCK_SIZE);

    blkioq_write(q, 0, buf, BLOCK_SIZE, NULL, 0);
    ret = blkioq_do_io(q, &comp, 1, 1, NULL);
    if (ret != 1) {
        fprintf(stderr, "FAIL: write do_io returned %d\n", ret);
        exit(1);
    }
    if (comp.ret != 0) {
        fprintf(stderr, "FAIL: write completion error: %s (%s)\n",
                strerror(-comp.ret),
                comp.error_msg ? comp.error_msg : "no msg");
        exit(1);
    }
    printf("poc: write OK\n");

    /* --- Read it back and verify --- */
    printf("poc: reading back %d bytes from offset 0...\n", BLOCK_SIZE);
    memset(buf, 0, BLOCK_SIZE);

    blkioq_read(q, 0, buf, BLOCK_SIZE, NULL, 0);
    ret = blkioq_do_io(q, &comp, 1, 1, NULL);
    if (ret != 1) {
        fprintf(stderr, "FAIL: read do_io returned %d\n", ret);
        exit(1);
    }
    if (comp.ret != 0) {
        fprintf(stderr, "FAIL: read completion error: %s (%s)\n",
                strerror(-comp.ret),
                comp.error_msg ? comp.error_msg : "no msg");
        exit(1);
    }

    /* Verify pattern */
    int mismatches = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (buf[i] != MAGIC_BYTE) {
            if (mismatches < 10)
                fprintf(stderr, "  mismatch at byte %d: got 0x%02X, expected 0x%02X\n",
                        i, buf[i], MAGIC_BYTE);
            mismatches++;
        }
    }
    if (mismatches > 0) {
        fprintf(stderr, "FAIL: %d byte mismatches in read-back\n", mismatches);
        exit(1);
    }
    printf("poc: read-back verification PASSED\n");

    /* --- Throughput benchmark: sequential 4K reads --- */
    printf("\npoc: benchmarking %d sequential 4K reads...\n", BENCH_ITERS);

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t offset = (uint64_t)(i % (capacity / BLOCK_SIZE)) * BLOCK_SIZE;

        blkioq_read(q, offset, buf, BLOCK_SIZE, NULL, 0);
        ret = blkioq_do_io(q, &comp, 1, 1, NULL);
        if (ret != 1) {
            fprintf(stderr, "FAIL: bench read do_io returned %d at iter %d\n",
                    ret, i);
            exit(1);
        }
        if (comp.ret != 0) {
            fprintf(stderr, "FAIL: bench read error at iter %d: %s\n",
                    i, strerror(-comp.ret));
            exit(1);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double secs = elapsed_sec(&t_start, &t_end);
    double iops = BENCH_ITERS / secs;
    double bw_mib = (BENCH_ITERS * (double)BLOCK_SIZE) / (secs * 1024 * 1024);

    printf("poc: %d reads in %.3f sec\n", BENCH_ITERS, secs);
    printf("poc: IOPS = %.0f\n", iops);
    printf("poc: throughput = %.1f MiB/s (%.1f MB/s)\n",
           bw_mib, bw_mib * 1.048576);

    /* --- Cleanup --- */
    printf("\npoc: cleanup...\n");
    blkio_unmap_mem_region(b, &region);
    blkio_free_mem_region(b, &region);
    blkio_destroy(&b);

    printf("poc: SUCCESS - all tests passed\n");
    return 0;
}
