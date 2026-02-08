# lblk-bench

Minimal-overhead I/O benchmarking tool using [libblkio](https://gitlab.com/libblkio/libblkio). Designed for benchmarking vhost-user-blk backends (e.g., ubiblk) with busy-loop polling and direct libblkio calls.

## Build

Prerequisites: libblkio (installed with pkg-config support), GCC, pthreads.

```bash
make
```

## Quick Start

### vhost-user-blk (with ubiblk)

Start ubiblk:
```bash
~/ubiblk/target/release/vhost-backend -f configs/bench.yaml
```

Run benchmark:
```bash
./lblk-bench --path /tmp/vhost.sock --rw randread --bs 4k --iodepth 32 --numjobs 4 --runtime 10
```

### io-uring (local file baseline)

```bash
truncate -s 1G /tmp/test-disk.raw
./lblk-bench --driver io-uring --path /tmp/test-disk.raw --rw randread --bs 4k --iodepth 32
```

## CLI Reference

### Required

| Arg | Description |
|-----|-------------|
| `--path PATH` | Device/socket path (meaning depends on `--driver`) |
| `--rw MODE` | I/O pattern: `read`, `write`, `randread`, `randwrite`, `readwrite`, `randrw` |

### Workload Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--bs SIZE` | `4k` | Block size (supports k/m/g suffixes) |
| `--iodepth N` | `1` | Outstanding I/Os per queue |
| `--numjobs N` | `1` | Parallel jobs (each gets its own queue and thread) |
| `--runtime SEC` | `10` | Duration in seconds |
| `--size SIZE` | device capacity | I/O region size per job |
| `--offset SIZE` | `0` | Starting offset for I/O |
| `--rwmixread PCT` | `50` | Read percentage for mixed workloads |
| `--ramp_time SEC` | `0` | Warmup seconds; stats reset after ramp |
| `--sync N` | `0` | Flush every N writes; 0 = disabled |

### libblkio Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--driver NAME` | `virtio-blk-vhost-user` | libblkio driver name |
| `--queue-size N` | `256` | Virtio queue size |

### Output Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--output-format FMT` | `normal` | Output format: `normal` or `json` |

## Example Output

```
lblk-bench: rw=randread, bs=4k, iodepth=32, numjobs=4, runtime=10s
  read: IOPS=320.0k, BW=1250MiB/s (1311MB/s)
    lat (usec): min=2.0, max=850.0, avg=12.5
    lat percentiles (usec):
     |  1.00th=[    3],  5.00th=[    4], 10.00th=[    5], 50.00th=[   10],
     | 90.00th=[   20], 99.00th=[   45], 99.90th=[  120], 99.99th=[  450]
  cpu: usr=25.3%, sys=0.1%
  ios: total=3200000, errors=0, flushes=0
```

## Architecture

- **Threading**: One thread per job, each with its own libblkio queue — no shared mutable state during the benchmark.
- **Memory**: One `blkio_mem_region` per worker, pre-allocated to hold `iodepth` buffers of `bs` bytes. Each in-flight I/O uses a dedicated buffer slot.
- **I/O Loop**: Busy-poll with `blkioq_do_io(q, comps, 0, iodepth, &zero_timeout)`. No sleeping, no eventfd.
- **Latency**: Per-request timestamps via `user_data` pointer. Log2 histogram for percentile computation.
- **Workload**: xorshift64 PRNG for random offsets (per-thread, no contention).

## License

MIT
