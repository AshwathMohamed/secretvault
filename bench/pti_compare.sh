#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# pti_compare.sh - measures the cost of KPTI by running syscall_bench twice:
# once with KPTI on (normal boot) and once with pti=off.
#
# !! WARNING !!
#  - It edits /etc/default/grub, installs a temporary systemd service and REBOOTS THE VM TWICE.
#  - Only for Ubuntu with GRUB, inside a VM, and take a snapshot first.
#  - The pti=off boot is vulnerable to Meltdown on purpose. Don't do this on a real machine.
#  - If something goes wrong:  sudo bench/pti_compare.sh abort   (removes pti=off, then reboot)
#
# usage: sudo bench/pti_compare.sh        (start)
#        sudo bench/pti_compare.sh abort  (undo)
# The script calls itself with "resume" after each reboot, you don't run that one yourself.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"             # ROOT = the project folder
ST=/var/lib/pti-compare                              # ST = folder where the script remembers its state between reboots
SVC=/etc/systemd/system/pti-compare.service          # SVC = temporary service that continues the script after a reboot
GRUB=/etc/default/grub                               # GRUB = boot options file that I edit to add pti=off
RES="$ROOT/results/pti-compare.txt"                  # RES = file with the results
BENCH="$ROOT/bench/syscall_bench"                    # BENCH = the benchmark program
MELT=/sys/devices/system/cpu/vulnerabilities/meltdown   # MELT = shows if KPTI is active

# print a line and also append it to the results file
log() { echo "$*" | tee -a "$RES"; }

# run the benchmark 3 times, $1 is "on" or "off" (which boot this is)
run_bench() {
  local i out   # i = run number, out = what the benchmark printed
  for i in 1 2 3; do
    out=$("$BENCH")
    log "  run $i: $out"
    echo "${out##*avg_ns_per_syscall=}" >> "$ST/$1.nums"   # keep only the number
  done
}

# average of the numbers saved for "on" or "off"
avg() { awk '{s+=$1} END {if (NR) printf "%.1f", s/NR}' "$ST/$1.nums"; }

# remove pti=off from the grub file
strip_pti() { sed -i 's/ pti=off//' "$GRUB"; }

# first part: measure with KPTI on, then set up pti=off and reboot
start() {
  [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
  [ -f "$ROOT/bench/syscall_bench.c" ] || { echo "missing bench/syscall_bench.c"; exit 2; }
  gcc -O2 -o "$BENCH" "$ROOT/bench/syscall_bench.c" || exit 2
  grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB" || { echo "no GRUB_CMDLINE_LINUX_DEFAULT line found"; exit 2; }
  mkdir -p "$ST" "$ROOT/results"
  rm -f "$ST"/*.nums
  : > "$RES"
  log "== pti-compare $(date) kernel $(uname -r) =="
  log "meltdown status (before): $(cat $MELT)"
  log "pti=on runs:"
  run_bench on
  cp "$GRUB" "${GRUB}.pti-compare.bak"   # backup of the grub file, just in case
  grep -q 'pti=off' "$GRUB" || sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/"$/ pti=off"/' "$GRUB"
  if ! grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=.*pti=off' "$GRUB"; then
    echo "could not add pti=off to $GRUB; restoring and stopping"
    cp "${GRUB}.pti-compare.bak" "$GRUB"
    exit 2
  fi
  echo off > "$ST/state"   # remember that the next boot is the pti=off one
  cat > "$SVC" <<EOT
[Unit]
Description=pti compare
After=multi-user.target

[Service]
Type=oneshot
ExecStart=$ROOT/bench/pti_compare.sh resume

[Install]
WantedBy=multi-user.target
EOT
  systemctl daemon-reload
  systemctl enable pti-compare.service
  update-grub
  echo "rebooting into pti=off in 10 seconds"
  sleep 10
  systemctl reboot
}

# runs after each reboot (started by the systemd service)
resume() {
  local st   # st = what the script was doing before the reboot: "off" or "restore"
  st=$(cat "$ST/state" 2>/dev/null) || exit 0
  if [ "$st" = off ]; then
    sleep 45   # wait for the system to settle after boot
    log ""
    log "meltdown status (pti=off boot): $(cat $MELT)"
    case "$(cat $MELT)" in
      *PTI*) log "WARNING: pti=off did not take effect on this boot" ;;
    esac
    log "pti=off runs:"
    run_bench off
    strip_pti
    echo restore > "$ST/state"
    update-grub
    systemctl reboot
  elif [ "$st" = restore ]; then
    sleep 20
    log ""
    log "meltdown status (restored): $(cat $MELT)"
    systemctl disable pti-compare.service
    rm -f "$SVC"
    systemctl daemon-reload
    log ""
    log "average ns per syscall: pti=on $(avg on)  pti=off $(avg off)"
    log "kpti tax per syscall (ns): $(awk -v a="$(avg on)" -v b="$(avg off)" 'BEGIN {printf "%.1f", a-b}')"
    log "== done =="
    rm -f "$ST/state"
  fi
}

# undo everything if the script got stuck
abort() {
  [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
  strip_pti
  systemctl disable pti-compare.service 2>/dev/null
  rm -f "$SVC" "$ST/state"
  systemctl daemon-reload
  update-grub
  echo "aborted; reboot to get pti back on"
}

case "${1:-start}" in
  start) start ;;
  resume) resume ;;
  abort) abort ;;
  *) echo "usage: sudo $0 [start|abort]" ;;
esac
