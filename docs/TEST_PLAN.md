# Test plan

Run **inside the VM guest**, as root, after a snapshot, on the kernel you will report (`uname -r`).
`tests/run_all.sh` automates T03 to T09, T12 to T14. Results are PASS / FAIL / INCONCLUSIVE; INCONCLUSIVE is never a pass.
The run is green only with 0 failures **and** 0 inconclusive.

| ID | Test | How | Expected |
|---|---|---|---|
| T01 | CPU / kernel status | `scripts/check_cpu.sh`, `uname -r` | Record meltdown, l1tf, mds lines and kernel version |
| T02 | Build + load | `make; sudo insmod module/secretvault.ko; dmesg \| tail` | Loads, prints "loaded". "cannot resolve" means no kprobes |
| T03 | Scanner positive control | `echo control > ctl` | `PASS scanner-sees-normal-alias` |
| T04a | Alloc | `echo alloc > ctl` | `alloc ok`, prints id, pfn, dmap |
| T04b | Hidden state | `check 0` | `PRESENT_ALIAS_CHECK: PASS` (present=0, nofault_read_ok=0, alias_present=0) |
| T04c | Residual PTE visible | same output | `alias_residual_np >= 1` (shows the scanner sees the stale entry; L1TF caveat) |
| T05 | kcore blind while closed | `tests/kcore_probe.py <dmap>` | `FULL_READ` with `pattern_words=0`, or `UNREADABLE`. Valid only if T07 passes |
| T06 | Window correctness | `access 0`, then `check 0` | `PASS secret-intact`, then hidden again |
| T07 | **Window exposure + kcore positive control** | `hold 0 3000` in one shell; `kcore_probe.py` in another | `FULL_READ pattern_words=512` during window; hidden afterwards (T07b) |
| T08 | Overhead | `bench 2000` | Record baseline vs vault alloc/free ns and window open/close ns |
| T09 | Free | `free 0` | `free ok` |
| T10 | KPTI baseline (manual) | `make -C bench`; boot with `pti=on`, then `pti=off`; run `bench/syscall_bench`; or `sudo bench/pti_compare.sh` to do both boots automatically | Record ns/syscall for both; this is the cost KPTI charges every process |
| T12 | Lifetime stress | `stress 4 2000` (x3), then `list` | `PASS no-uaf-no-errors`; `secrets=0`; dmesg clean. Repeat on a KASAN kernel if available |
| T13 | Negative cases | `free 99`, `access 5`, `check 7`, `hold 77 10`, `bogus` | Each returns `ERROR`, no oops |
| T14 | Unload with live secrets | `alloc` x3 then `rmmod secretvault` | Clean unload; dmesg shows no BUG/Oops/WARNING |

**Deferred (not part of this plan):** T11, running a Meltdown proof-of-concept. Revisit only after every test above passes.

**Pass criteria for publishing:** run_all.sh summary shows 0 failed and 0 inconclusive, with T01 and T10 recorded
in `docs/RESULTS_TEMPLATE.md`. **If anything oopses:** revert the snapshot, save `dmesg`, and investigate before changing code.
