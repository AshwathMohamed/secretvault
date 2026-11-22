#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# check_cpu.sh - prints which CPU bugs (Meltdown family) this machine has and how Linux handles them.
# Run it inside the VM.

# f = name of one vulnerability file under /sys/devices/system/cpu/vulnerabilities/
for f in meltdown l1tf mds spectre_v1 spectre_v2; do
  printf "%-12s %s\n" "$f" "$(cat /sys/devices/system/cpu/vulnerabilities/$f 2>/dev/null || echo n/a)"
done
grep -m1 'model name' /proc/cpuinfo                                  # which CPU
grep -o -m1 'pti\|pcid' /proc/cpuinfo | sort -u | tr '\n' ' '; echo   # CPU flags related to KPTI
echo "cmdline: $(cat /proc/cmdline)"                                  # boot options (shows pti=off if I set it)
