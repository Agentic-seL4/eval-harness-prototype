#!/usr/bin/env bash
# Before a live demo: check the toolchain, the attacker's TCP port, build every image
# DEMO.md uses, and run each act once. Prints "ready" at the end, or stops at the
# first problem with a message saying what failed.
# Usage: MICROKIT_SDK=/path/to/microkit-sdk-2.3.1 scripts/preflight.sh [PORT]
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."
port=${1:-4444}
: "${MICROKIT_SDK:?Set MICROKIT_SDK to the unpacked Microkit SDK 2.3.1 directory}"

step() { printf '\n== %s\n' "$1"; }
fail() { printf '\npreflight FAILED: %s\n' "$1" >&2; exit 1; }

step "toolchain and a test boot (scripts/check-env.sh)"
scripts/check-env.sh >/dev/null || fail "the toolchain check failed; run scripts/check-env.sh to see why"
echo "ok"

step "attacker port 127.0.0.1:$port is free"
python3 - "$port" 2>/dev/null <<'EOF' || fail "port $port is in use, or local listening is blocked (Claude Code: sandbox.network.allowLocalBinding)"
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.close()
EOF
echo "ok"

step "build the images for the live TCP demo (open and fenced)"
for policy in open fenced; do
    make -s INPUT=tcp POLICY="$policy" all >/dev/null || fail "building the $policy TCP image"
done
echo "ok"

step "the live TCP path end to end (the script plays the attacker)"
out=$(make -s INPUT=tcp POLICY=open SEND=1 PORT="$port" run 2>&1) || fail "the open TCP run did not finish"
echo "$out" | grep -q 'attacker< OBS {"tool":"Fetch","args":\["Data 1"\]}' \
    || fail "the attacker did not receive the expected OBS line"
echo "ok: the attacker received the OBS line"

step "make demo (the three acts)"
python3 scripts/demo.py >/dev/null || fail "make demo reported a problem; run it to see which act"
echo "ok"

step "make bypass (the confinement table)"
python3 scripts/run_bypass.py >/dev/null || fail "a confinement check failed; see build/bypass/report.md"
echo "ok"

printf '\nready: every step in DEMO.md has run once on this machine.\n'
