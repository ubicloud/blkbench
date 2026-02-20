# blkbench

Minimal-overhead I/O benchmarking tool using [libblkio](https://gitlab.com/libblkio/libblkio). Designed for benchmarking vhost-user-blk backends (e.g., ubiblk) with busy-loop polling and direct libblkio calls.

## Requirements

### blkbench

- [libblkio](https://gitlab.com/libblkio/libblkio) (installed with pkg-config support)
- GCC
- pthreads

### io-profile

- `bpftrace` (requires root)
- `sysstat` (`iostat`, `mpstat`)
- `awk`

## Build

```bash
make
```

Run unit tests:

```bash
make test
```

## Quick Start

### vhost-user-blk (with ubiblk)

Start ubiblk:
```bash
~/ubiblk/target/release/vhost-backend -f configs/basic.yaml
```

Run benchmark:
```bash
./blkbench --path /tmp/vhost.sock --rw randread --bs 4k --iodepth 32 --numjobs 4 --runtime 10
```

### io_uring (local file baseline)

```bash
truncate -s 1G /tmp/test-disk.raw
./blkbench --driver io_uring --path /tmp/test-disk.raw --rw randread --bs 4k --iodepth 32
```

### JSON output

```bash
./blkbench --driver io_uring --path /tmp/test-disk.raw --rw randread --output-format json | jq .
```

## CLI Reference

### Required

| Arg | Description |
|-----|-------------|
| `--path PATH` | Device/socket path (meaning depends on `--driver`) |
| `--rw MODE` | I/O pattern: `read`, `write`, `randread`, `randwrite`, `readwrite`, `randrw`, `verify-flush`, `verify-pipeline` |

### Workload Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--bs SIZE` | `4k` | Block size (supports k/m/g suffixes, must be power of 2, >= 512) |
| `--iodepth N` | `1` | Outstanding I/Os per queue |
| `--numjobs N` | `1` | Parallel jobs (each gets its own queue and thread) |
| `--runtime SEC` | `10` | Duration in seconds |
| `--size SIZE` | device capacity | I/O region size per job |
| `--offset SIZE` | `0` | Starting offset for I/O |
| `--rwmixread PCT` | `50` | Read percentage for mixed workloads |
| `--ramp_time SEC` | `0` | Warmup seconds; stats reset after ramp |
| `--sync N` | `0` | Flush every N writes; 0 = disabled |

### Verify Options

Used with `--rw verify-flush` and `--rw verify-pipeline` modes.

| Arg | Default | Description |
|-----|---------|-------------|
| `--verify-sectors MIN:MAX` | `1:16` | Sectors per write region (range, inclusive) |
| `--verify-inject-fault` | off | Inject a single-byte corruption per thread to test fault detection |

### libblkio Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--driver NAME` | `virtio-blk-vhost-user` | libblkio driver name (e.g., `io_uring`, `virtio-blk-vhost-user`) |
| `--direct 0\|1` | `1` | Use direct I/O, bypass page cache |

### Output Options

| Arg | Default | Description |
|-----|---------|-------------|
| `--output-format FMT` | `normal` | Output format: `normal` or `json` |
| `--eta-interval SEC` | `2` | Progress line interval to stderr; `0` disables |
| `--help` | | Show usage information |
| `--version` | | Show version |

## Verify Modes

### verify-flush

Writes data with CRC32 checksums, flushes, then reads back and verifies integrity. Tests write persistence through the I/O stack.

```bash
./blkbench --driver io_uring --path /tmp/test-disk.raw --rw verify-flush --numjobs 4
```

### verify-pipeline

Circular pipeline where each thread writes data that the next thread reads and verifies. Tests cross-thread write visibility without explicit flush.

```bash
./blkbench --driver io_uring --path /tmp/test-disk.raw --rw verify-pipeline --numjobs 4
```

Fault injection (for testing the verifier itself):

```bash
./blkbench --driver io_uring --path /tmp/test-disk.raw --rw verify-flush --verify-inject-fault
```

## Example Output

```
blkbench: rw=randread, bs=4k, iodepth=32, numjobs=4, runtime=10s
  read: IOPS=320.0k, BW=1250MiB/s (1311MB/s)
    lat (usec): min=2.0, max=850.0, avg=12.5
    lat percentiles (usec):
     |  1.00th=[    3],  5.00th=[    4], 10.00th=[    5], 50.00th=[   10],
     | 90.00th=[   20], 99.00th=[   45], 99.90th=[  120], 99.99th=[  450]
  cpu: usr=25.3%, sys=0.1%
  ios: total=3200000, errors=0, flushes=0
```

## io-profile

A reusable IO + CPU profiling wrapper. Runs any command and produces a standardized report with block IO metrics, syscall tracking, CPU utilization, and per-thread breakdown.

### Usage

```bash
sudo ./io-profile [options] -- command [args...]
```

### Options

| Arg | Default | Description |
|-----|---------|-------------|
| `-o, --output DIR` | `./io-profile-results` | Output directory for reports |
| `-d, --device DEV` | auto-detect | Block device to monitor |
| `-p, --pid PID` | | Only trace this PID and children |
| `--json` | off | Also emit machine-readable JSON summary |
| `-v, --verbose` | off | Show progress messages |

### Examples

```bash
sudo ./io-profile -- dd if=/dev/zero of=/tmp/test bs=1M count=1000
sudo ./io-profile --json -o results/ -- dd if=/dev/sda of=/dev/null bs=4k count=100000
sudo ./io-profile -d nvme0n1 -- fio job.fio
```

### What it collects

- **Block IO**: throughput, IOPS, queue depth distribution, block size distribution, IO latency percentiles, sequential vs random ratio, read/write split
- **Syscalls**: fsync/fdatasync/sync_file_range counts and rates, O_DIRECT detection
- **CPU**: utilization percentiles, iowait, user/system split, context switch rate
- **Per-thread**: IOPS, read/write bytes, fsync count, sequential percentage per thread

### Example output

```
=== IO Profile: dd if=/dev/zero of=/tmp/io-profile-dd-test bs=1M count=500 oflag=dsync ===
Duration: 0.9s | Device: nvme1n1 | Kernel: 6.8.0-94-generic

IO Summary:
  Throughput:    Read 0.0 MB/s | Write 559.9 MB/s
  IOPS:          Read 4 | Write 5,559
  IO Threads:    4
  R/W Ratio:     0% read / 100% write
  Sequential:    79%
  fsync calls:   1 (1.1/s) [fsync=1 fdatasync=0 sync_file_range=0]
  O_DIRECT:      No

Histograms:
  Queue Depth:   p25=21   p50=30   p75=33   p99=37   max=37
  Block Size:    p25=128K p50=128K p75=128K p99=128K max=128K
  IO Latency:    p25=74us   p50=162us  p75=248us  p99=333us  max=342us

CPU Summary:
  CPU Usage:     p25=9% p50=11% p75=11% p99=11%
  IOWait:        p25=1% p50=1% p75=3% p99=3%
  User/System:   0% user / 0% system
  Ctx Switches:  115,467/s

Per-Thread IO Breakdown:
  Thread                   |    IOPS |  Read MB |  Write MB |   fsync | Seq%
  -------------------------|---------|----------|-----------|---------|-----
  dd (tid 1917002)         |   4,446 |      0.0 |     500.0 |       0 |  87%
  jbd2/nvme1n1p3- (tid 571) |   1,113 |      0.0 |       3.9 |       0 |  50%
```

## Architecture

- **Threading**: One thread per job, each with its own libblkio queue — no shared mutable state during the benchmark.
- **Memory**: One `blkio_mem_region` per worker, pre-allocated to hold `iodepth` buffers of `bs` bytes. Each in-flight I/O uses a dedicated buffer slot.
- **I/O Loop**: Busy-poll with `blkioq_do_io(q, comps, 0, iodepth, &zero_timeout)`. No sleeping, no eventfd.
- **Latency**: Per-request timestamps via `user_data` pointer. Log2 histogram for percentile computation.
- **Workload**: xorshift64 PRNG for random offsets (per-thread, no contention).
- **Verify**: CRC32 checksums (IEEE polynomial) with thread-safe bump allocator for write-verify workflows.

## License

MIT
