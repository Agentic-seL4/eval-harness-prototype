#!/usr/bin/env bash
# T1: check the toolchain, then build and boot the SDK's hello example on QEMU.
# Usage: MICROKIT_SDK=/path/to/microkit-sdk-2.3.1 scripts/check-env.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
: "${MICROKIT_SDK:?Set MICROKIT_SDK to the unpacked Microkit SDK 2.3.1 directory}"
MICROKIT_SDK=$(cd "$MICROKIT_SDK" && pwd)
board=qemu_virt_aarch64
config=debug
build="$here/../build/hello"

missing=0
for tool in clang ld.lld qemu-system-aarch64 make python3; do
    if ! command -v "$tool" >/dev/null; then
        echo "missing: $tool" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || { echo "Install the missing tools first (see README)." >&2; exit 1; }

sdk_version=$(cat "$MICROKIT_SDK/VERSION")
[ "$sdk_version" = "2.3.1" ] || echo "warning: expected Microkit SDK 2.3.1, found $sdk_version" >&2

echo "== versions"
echo "Microkit SDK $sdk_version ($MICROKIT_SDK)"
clang --version | head -1
ld.lld --version
qemu-system-aarch64 --version | head -1
python3 --version

echo "== build $board/$config hello"
mkdir -p "$build"
make -s -C "$MICROKIT_SDK/example/hello" BUILD_DIR="$build" MICROKIT_SDK="$MICROKIT_SDK" \
    MICROKIT_BOARD="$board" MICROKIT_CONFIG="$config" LLVM=True

echo "== boot on QEMU"
python3 "$here/run_qemu.py" "$build/loader.img" --until "hello, world" --timeout 30 \
    --log "$build/qemu.log" | tail -4
echo "== environment OK: serial log in build/hello/qemu.log"
