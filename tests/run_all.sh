#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# run_all.sh - runs all my automated tests. Run it as root INSIDE the VM:
#     sudo tests/run_all.sh
# If a test can't reach a clear answer it says INCONCLUSIVE, never PASS.

set -u                          # using a variable I never set is an error
cd "$(dirname "$0")/.."         # go to the project folder, no matter where I started the script
D=/sys/kernel/debug/secretvault   # the debugfs folder of my module
mkdir -p results
OUT=results/run-$(date +%Y%m%d-%H%M%S).log   # log file for this run, named with the date and time
exec > >(tee "$OUT") 2>&1       # everything printed goes to the screen AND into the log file

pass=0; fail=0; inc=0           # counters: passed, failed, inconclusive

# helper functions
ok()   { echo "[PASS] $1"; pass=$((pass+1)); }              # count a pass
bad()  { echo "[FAIL] $1"; fail=$((fail+1)); }              # count a fail
unk()  { echo "[INCONCLUSIVE] $1"; inc=$((inc+1)); }        # count an inconclusive
cmd()  { { echo "$1" > $D/ctl; } 2>/dev/null; cat $D/result; }   # send a command to the module and print its answer
probe(){ python3 tests/kcore_probe.py "$1"; }               # try to read an address through /proc/kcore

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
KVER=$(uname -r)                # kernel version of this VM
echo "== environment =="
echo "kernel : $KVER"
echo "headers: $( [ -d /lib/modules/$KVER/build ] && echo present || echo MISSING )"
echo "meltdown: $(cat /sys/devices/system/cpu/vulnerabilities/meltdown)"
echo "cmdline : $(cat /proc/cmdline)"
[ -d /lib/modules/$KVER/build ] || { echo "install headers for $KVER (scripts/setup_vm.sh)"; exit 2; }

mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
make -C module >/dev/null 2>results/build-errors.txt || { echo "module build failed: see results/build-errors.txt"; exit 2; }
rmmod secretvault 2>/dev/null   # remove an old copy of the module if it is loaded
DM0=$(dmesg | wc -l)            # how many dmesg lines exist now, so later I only look at NEW lines
insmod module/secretvault.ko || { echo "insmod failed (see dmesg)"; exit 2; }
trap 'rmmod secretvault 2>/dev/null' EXIT   # always unload the module when the script ends

echo; echo "== T03 scanner positive control (normal page) =="
r=$(cmd control); echo "$r"     # r = the module's answer to the last command
echo "$r" | grep -q "PASS scanner-sees-normal-alias" && ok "T03 scanner finds a normal page's mapping" || bad "T03 scanner"

echo; echo "== T04 alloc + hidden-state checks =="
r=$(cmd alloc); echo "$r"
echo "$r" | grep -q "alloc ok" && ok "T04a alloc" || bad "T04a alloc"
DMAP=$(echo "$r" | grep -o 'dmap=[0-9a-fx]*' | head -1 | cut -d= -f2)   # DMAP = kernel address of the secret page
[[ $DMAP == 0x* ]] || DMAP=0x$DMAP
r=$(cmd "check 0"); echo "$r"
echo "$r" | grep -q "PRESENT_ALIAS_CHECK: PASS" && ok "T04b no present alias, not readable" || bad "T04b present alias check"
RES=$(echo "$r" | grep -o 'alias_residual_np=[0-9]*' | cut -d= -f2)      # RES = leftover non-present entries found
[ "${RES:-0}" -ge 1 ] && ok "T04c scanner sees stale non-present PTE (residual_np=$RES; L1TF-class caveat)" \
                      || bad "T04c residual non-present PTE not seen (scanner problem?)"

echo; echo "== T05 /proc/kcore while closed =="
r=$(probe "$DMAP"); echo "$r"
T05_STATUS=$(echo "$r" | grep -o 'status=[A-Z_]*' | cut -d= -f2)         # how the read went (FULL_READ, UNREADABLE, ...)
T05_WORDS=$(echo "$r" | grep -o 'pattern_words=[0-9]*' | cut -d= -f2)    # how many secret words were seen (0 = none)

echo; echo "== T06 access window =="
r=$(cmd "access 0"); echo "$r"
echo "$r" | grep -q "PASS secret-intact" && ok "T06a secret intact via window" || bad "T06a window"
r=$(cmd "check 0"); echo "$r"
echo "$r" | grep -q "PRESENT_ALIAS_CHECK: PASS" && ok "T06b hidden again after window" || bad "T06b re-hide"

echo; echo "== T07 positive control for kcore: window open (known exposure, expected visible) =="
( { echo "hold 0 3000" > $D/ctl; } 2>/dev/null ) &   # keep the window open 3 seconds, in the background
HOLD_PID=$!                      # remember that background process so I wait only for it
sleep 1
r=$(probe "$DMAP"); echo "during window: $r"
wait "$HOLD_PID"
if echo "$r" | grep -q "status=FULL_READ pattern_words=512"; then
  ok "T07 kcore CAN read the secret during the window (known limitation; probe is trustworthy)"
  T07_OK=1                       # T07_OK = 1 means the probe really can see the secret when it is visible
else
  bad "T07 probe did not see the secret even with the window open (probe or timing problem)"
  T07_OK=0
fi

echo; echo "== T05 verdict (needs T07's positive control) =="
if [ "$T07_OK" = 1 ] && { [ "$T05_STATUS" = FULL_READ ] && [ "${T05_WORDS:-1}" = 0 ] || [ "$T05_STATUS" = UNREADABLE ]; }; then
  ok "T05 kcore cannot see the secret while closed (status=$T05_STATUS)"
else
  unk "T05 closed-state probe not conclusive (status=$T05_STATUS words=$T05_WORDS, control ok=$T07_OK)"
fi
r=$(probe "$DMAP"); echo "after window: $r"
if echo "$r" | grep -Eq "status=FULL_READ pattern_words=0|status=UNREADABLE"; then ok "T07b hidden again after window"; else bad "T07b after window"; fi

echo; echo "== T08 benchmark =="
cmd "bench 2000"

echo; echo "== T09 free =="
r=$(cmd "free 0"); echo "$r"
echo "$r" | grep -q "free ok" && ok "T09 free" || bad "T09 free"

echo; echo "== T12 lifetime stress: concurrent access racing free (use with a KASAN kernel if you have one) =="
for n in 1 2 3; do               # n = which of the 3 stress runs this is
  r=$(cmd "stress 4 2000"); echo "$r"
  echo "$r" | grep -q "PASS no-uaf-no-errors" && ok "T12.$n stress" || bad "T12.$n stress"
done
r=$(cmd list); echo "$r"
echo "$r" | grep -q "secrets=0" && ok "T12 no leaked secrets" || bad "T12 leaked secrets"

echo; echo "== T13 negative cases =="
for c in "free 99" "access 5" "check 7" "hold 77 10" "bogus"; do   # c = one bad command, each must be rejected
  r=$(cmd "$c"); echo "[$c] $r"
  echo "$r" | grep -q "ERROR" && ok "T13 '$c' rejected cleanly" || bad "T13 '$c' not rejected"
done

echo; echo "== T14 unload with live secrets =="
cmd alloc >/dev/null; cmd alloc >/dev/null; cmd alloc >/dev/null
rmmod secretvault && ok "T14 rmmod with 3 live secrets" || bad "T14 rmmod"
trap - EXIT
# only look at dmesg lines that appeared during this run
if dmesg | tail -n +$((DM0+1)) | grep -E "BUG:|Oops|WARNING|KASAN|secretvault: (FAILED|cannot)"; then
  bad "dmesg shows problems (see above)"
else
  ok "dmesg clean for the whole run"
fi

echo; echo "== SUMMARY: $pass passed, $fail failed, $inc inconclusive  (log: $OUT) =="
[ "$fail" = 0 ] && [ "$inc" = 0 ]   # exit code 0 only if everything passed
