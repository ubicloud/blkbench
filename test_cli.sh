#!/bin/bash
# test_cli.sh - CLI argument and exit code tests
#
# Verifies:
# - --help exits 0
# - --version exits 0 and prints version
# - Missing --path exits non-zero
# - Missing --rw exits non-zero
# - Invalid args exit non-zero

set -uo pipefail

PASS=0
FAIL=0

check() {
    local desc="$1" cond="$2"
    if eval "$cond"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "== CLI tests =="

# --help exits 0
check "--help exits 0" './blkbench --help >/dev/null 2>&1'

# --help includes usage text
HELP=$(./blkbench --help 2>&1)
check "--help mentions --path" 'echo "$HELP" | grep -q "\-\-path"'
check "--help mentions --rw" 'echo "$HELP" | grep -q "\-\-rw"'

# --version exits 0
check "--version exits 0" './blkbench --version >/dev/null 2>&1'

# --version prints version string
VER=$(./blkbench --version 2>&1)
check "--version prints blkbench" 'echo "$VER" | grep -q "blkbench"'
check "--version prints version number" 'echo "$VER" | grep -qE "[0-9]+\.[0-9]+\.[0-9]+"'

# Missing --path exits non-zero
check "missing --path exits non-zero" '! ./blkbench --rw randread >/dev/null 2>&1'

# Missing --rw exits non-zero
check "missing --rw exits non-zero" '! ./blkbench --path /tmp/foo >/dev/null 2>&1'

# Invalid --rw exits non-zero
check "invalid --rw exits non-zero" '! ./blkbench --path /tmp/foo --rw badmode >/dev/null 2>&1'

# Invalid --bs exits non-zero
check "invalid --bs=0 exits non-zero" '! ./blkbench --path /tmp/foo --rw read --bs 0 >/dev/null 2>&1'

# Invalid --bs (not power of 2) exits non-zero
check "invalid --bs=1000 exits non-zero" '! ./blkbench --path /tmp/foo --rw read --bs 1000 >/dev/null 2>&1'

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
