#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# build_kernel.sh - OPTIONAL. Builds a custom kernel (for example a KASAN debug kernel).
# Not needed to run my project, the normal Ubuntu kernel works.
# usage: scripts/build_kernel.sh [kernel source folder]
set -e
SRC=${1:-$HOME/linux}   # SRC = where the kernel source is (or will be cloned to)
[ -d "$SRC" ] || git clone --depth 1 --branch v6.6 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$SRC"
cd "$SRC"
cp /boot/config-"$(uname -r)" .config   # start from the config of the running kernel
# Ubuntu configs point to signing keys and BTF that break a self-build, so switch those off
scripts/config --set-str SYSTEM_TRUSTED_KEYS "" --set-str SYSTEM_REVOCATION_KEYS ""
scripts/config --disable DEBUG_INFO_BTF --disable MODULE_SIG --disable MODULE_SIG_ALL
# things my module needs (kprobes, debugfs, /proc/kcore) and the KPTI/secretmem options I study
scripts/config --enable DEBUG_INFO --enable KPROBES --enable DEBUG_FS --enable PROC_KCORE \
               --enable SECRETMEM --enable PAGE_TABLE_ISOLATION
scripts/config --set-str LOCALVERSION "-sv"   # adds "-sv" to the kernel name so I can recognise it
make olddefconfig
make -j"$(nproc)"
sudo make modules_install
sudo make install
echo "Reboot into the new kernel. Take snapshot 'custom-kernel-boots'."
