#!/bin/bash
# test_output.sh - Validate lblk-bench output formatting
#
# Runs short benchmarks with io_uring on a tmpfs file and checks:
# - Human-readable output has all required sections
# - JSON output is valid and has all required fields
#
# Requires: lblk-bench binary, jq, tmpfs-backed /tmp

set -euo pipefail

PASS=0
FAIL=0
TESTFILE="/tmp/lblk-bench-test-output.raw"

check() {
    local desc="$1" cond="$2"
    if eval "$cond"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() { rm -f "$TESTFILE" /tmp/lblk-out-*.txt; }
trap cleanup EXIT
dd if=/dev/zero of="$TESTFILE" bs=1M count=64 2>/dev/null

echo "== Human-readable output (randread) =="
./lblk-bench --driver io_uring --path "$TESTFILE" --rw randread \
    --bs 4k --iodepth 32 --numjobs 1 --runtime 1 > /tmp/lblk-out-human.txt 2>&1

HUMAN=$(cat /tmp/lblk-out-human.txt)

# Header line
check "header has rw=" 'echo "$HUMAN" | grep -q "^lblk-bench: rw=randread"'
check "header has bs=4k" 'echo "$HUMAN" | grep -q "bs=4k"'
check "header has iodepth=32" 'echo "$HUMAN" | grep -q "iodepth=32"'
check "header has numjobs=1" 'echo "$HUMAN" | grep -q "numjobs=1"'
check "header has runtime=1s" 'echo "$HUMAN" | grep -q "runtime=1s"'

# IOPS+BW line
check "read line has IOPS=" 'echo "$HUMAN" | grep -q "read: IOPS="'
check "read line has BW=" 'echo "$HUMAN" | grep -q "BW=.*MiB/s"'
check "read line has MB/s" 'echo "$HUMAN" | grep -q "MB/s)"'

# Latency line
check "lat line present" 'echo "$HUMAN" | grep -q "lat (.*): min=.*, max=.*, avg="'

# Percentile table
check "percentile header" 'echo "$HUMAN" | grep -q "lat percentiles"'
check "p1 present" 'echo "$HUMAN" | grep -q "1.00th="'
check "p50 present" 'echo "$HUMAN" | grep -q "50.00th="'
check "p99 present" 'echo "$HUMAN" | grep -q "99.00th="'
check "p99.9 present" 'echo "$HUMAN" | grep -q "99.90th="'
check "p99.99 present" 'echo "$HUMAN" | grep -q "99.99th="'

# CPU line
check "cpu line present" 'echo "$HUMAN" | grep -q "cpu: usr=.*%, sys=.*%"'

# IOs line
check "ios line present" 'echo "$HUMAN" | grep -q "ios: total=.*, errors=.*, flushes="'

echo ""
echo "== JSON output (randread) =="
./lblk-bench --driver io_uring --path "$TESTFILE" --rw randread \
    --bs 4k --iodepth 32 --numjobs 1 --runtime 1 \
    --output-format json > /tmp/lblk-out-json.txt 2>&1

# Validate JSON
check "JSON is valid" 'jq . /tmp/lblk-out-json.txt >/dev/null 2>&1'

# Check required fields
check "json has job.rw" 'jq -e ".job.rw" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has job.bs" 'jq -e ".job.bs" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has job.iodepth" 'jq -e ".job.iodepth" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has job.numjobs" 'jq -e ".job.numjobs" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has job.driver" 'jq -e ".job.driver" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has iops" 'jq -e ".iops" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has bw_bytes" 'jq -e ".bw_bytes" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has read_iops" 'jq -e ".read_iops" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has write_iops" 'jq -e ".write_iops" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has lat_ns.min" 'jq -e ".lat_ns.min" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has lat_ns.max" 'jq -e ".lat_ns.max" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has lat_ns.mean" 'jq -e ".lat_ns.mean" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has lat_ns.percentiles" 'jq -e ".lat_ns.percentiles" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has cpu.usr" 'jq -e ".cpu.usr" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has cpu.sys" 'jq -e ".cpu.sys" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has ios_total" 'jq -e ".ios_total" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has errors" 'jq -e ".errors" /tmp/lblk-out-json.txt >/dev/null 2>&1'
check "json has flushes" 'jq -e ".flushes" /tmp/lblk-out-json.txt >/dev/null 2>&1'

# Sanity: IOPS should be > 0
IOPS=$(jq '.iops' /tmp/lblk-out-json.txt)
check "json iops > 0" '[ "$(echo "$IOPS > 0" | bc)" = "1" ]'

# Sanity: lat min <= mean <= max
MIN=$(jq '.lat_ns.min' /tmp/lblk-out-json.txt)
MAX=$(jq '.lat_ns.max' /tmp/lblk-out-json.txt)
MEAN=$(jq '.lat_ns.mean' /tmp/lblk-out-json.txt)
check "lat min <= mean" '[ "$(echo "$MIN <= $MEAN" | bc)" = "1" ]'
check "lat mean <= max" '[ "$(echo "$MEAN <= $MAX" | bc)" = "1" ]'

# CPU sanity: non-negative
USR=$(jq '.cpu.usr' /tmp/lblk-out-json.txt)
SYS=$(jq '.cpu.sys' /tmp/lblk-out-json.txt)
check "cpu usr >= 0" '[ "$(echo "$USR >= 0" | bc)" = "1" ]'
check "cpu sys >= 0" '[ "$(echo "$SYS >= 0" | bc)" = "1" ]'

echo ""
echo "== Mixed workload output (randrw) =="
./lblk-bench --driver io_uring --path "$TESTFILE" --rw randrw \
    --bs 4k --iodepth 16 --numjobs 1 --runtime 1 --rwmixread 70 \
    > /tmp/lblk-out-mixed.txt 2>&1

MIXED=$(cat /tmp/lblk-out-mixed.txt)
check "mixed has read line" 'echo "$MIXED" | grep -q "read:.*IOPS="'
check "mixed has write line" 'echo "$MIXED" | grep -q "write:.*IOPS="'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
