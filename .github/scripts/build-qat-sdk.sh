#!/usr/bin/env bash
# Build only the legacy userspace libraries in a clean, writable SDK checkout.
# No kernel modules are built/installed and no devices or services are started.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: bash $0 /path/to/qat-legacy-linux" >&2
    exit 2
fi

qat_source="$(cd -- "$1" && pwd)"
if [[ ! -f "$qat_source/configure" || ! -f "$qat_source/quickassist/include/cpa.h" ]]; then
    echo 'Expected a legacy QAT source checkout with configure and SDK headers.' >&2
    exit 1
fi

# Hosted runners may use a kernel whose matching headers are unavailable from
# apt. Userspace compilation only needs an installed, prepared header tree for
# the release's configure checks, rather than headers matching the running OS.
if [[ -z "${KERNEL_SOURCE_ROOT:-}" ]]; then
    mapfile -t qat_header_candidates < <(
        find /usr/src -mindepth 1 -maxdepth 1 -type d \
            -name 'linux-headers-*-generic' -print | sort -V
    )
    if [[ ${#qat_header_candidates[@]} -eq 0 ]]; then
        echo 'Install linux-headers-generic or set KERNEL_SOURCE_ROOT explicitly.' >&2
        exit 1
    fi
    KERNEL_SOURCE_ROOT="${qat_header_candidates[-1]}"
fi
KERNEL_SOURCE_ROOT="$(cd -- "$KERNEL_SOURCE_ROOT" && pwd)"
if [[ ! -r "$KERNEL_SOURCE_ROOT/include/config/kernel.release" || ! -r "$KERNEL_SOURCE_ROOT/Makefile" ]]; then
    echo 'KERNEL_SOURCE_ROOT must identify a prepared kernel-header tree.' >&2
    exit 1
fi
export KERNEL_SOURCE_ROOT

echo "Building legacy QAT userspace libraries with headers at $KERNEL_SOURCE_ROOT"
cd -- "$qat_source"
./configure --prefix=/opt/qat --enable-icp-sriov=host

# The legacy build has shared clean prerequisites; keep it serial and skip
# cleanup in this clean checkout, including unused kernel cleanup recipes.
make -j1 quickassist-user ICP_NO_CLEAN=1

test -s build/libqat_s.so
test -s build/libusdm_drv_s.so
echo "Userspace SDK ready in $qat_source/build; no hardware was accessed."
