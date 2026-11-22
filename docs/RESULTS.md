# Results

- Date: 2026-11-22
- Guest kernel (`uname -r`): 7.0.0-43-generic
- Kernel command line: BOOT_IMAGE=/boot/vmlinuz-7.0.0-43-generic root=UUID=fd1df36b-00f3-4a5c-a6b1-ae6e605fff33 ro quiet splash
- Meltdown status: Mitigation: PTI (Vulnerable with pti=off)
- run_all.sh summary: 21 passed, 0 failed, 0 inconclusive
- Raw output: `docs/logs/run_all-console-2026-11-22.txt`, `docs/logs/pti-compare.txt`

| Test | Result | Notes / numbers |
|---|---|---|
| T01 | partial | kernel and meltdown status recorded; l1tf and mds not recorded (`scripts/check_cpu.sh` not run) |
| T02 | PASS | built against 7.0.0-43 headers (only a compiler-name warning), loaded, dmesg printed "loaded" |
| T03 | PASS | scanner finds a normal page, level=2 (2 MB entry), present=1 |
| T04a/b/c | PASS | secret hidden: present=0, level=1 (huge page split), residual_np = 1 |
| T05 | PASS | probe status = FULL_READ, pattern_words=0, nonzero_bytes=0 |
| T06 | PASS | window opens, secret intact (mismatches=0), hidden again afterwards |
| T07 / T07b | PASS | pattern_words during window: 512, after window: 0 |
| T08 | measured | baseline 414 ns / vault 201,155 ns / window 183,257 ns (avg per op, 2000 iters) |
| T09 | PASS | |
| T10 | measured | pti=on 601.2 ns / pti=off 528.3 ns per syscall (3 runs each, 5,000,000 iters); KPTI tax 72.9 ns |
| T12 | PASS | 3 runs, 4 threads x 2000 iters: ok=54/35/29, freed_under_us=7946/7965/7971, errors=0 |
| T13 | PASS | 5 bad commands rejected cleanly |
| T14 | PASS | rmmod with 3 live secrets; dmesg clean for the whole run |

## Observations

- The secret is unreachable while the window is closed (T04, T05) and fully readable through /proc/kcore while it is open (T07, 512 of 512 pattern words). The window exposure is the known limitation.
- T05 reports status=FULL_READ with zeros rather than an error, because /proc/kcore returns zeros for an unmapped page. The meaningful value is pattern_words=0, and T07 proves the probe can see the pattern when the page is mapped.
- Hiding one page splits its 2 MB direct-map entry into 4 KB entries (level 2 becomes level 1).
- One non-present PTE still holds the secret's page number (residual_np=1). L1TF-class exposure is not covered.
- Cost: opening and closing the window costs about 183 us, versus about 0.4 us for a normal page alloc/free (roughly 400 to 500 times slower). The cause was not measured; TLB flushes are the likely suspect.
- KPTI costs about 73 ns per syscall here (roughly 12%), with run-to-run spread of about 20 to 30 ns, measured on two different boots. One window costs about as much as the KPTI tax on 2,500 syscalls. At 1,000,000 syscalls per second the break-even is about 400 secret accesses per second.
- The cost comparison is not a protection comparison: KPTI protects all kernel memory all the time, the vault protects only its own pages and only while the window is closed.
- In the stress test almost every access (about 99.6%) was refused with -ENODEV after the owner freed, so the case of an access still running during the free is exercised only lightly. No KASAN kernel was used, so errors=0 is evidence, not proof, of freedom from use-after-free.
- Two bugs in run_all.sh were found and fixed during this run: a bare `wait` that hung at T07 (now waits for the hold process only) and a case-insensitive dmesg search that matched the word "debug".
- Single VM, single kernel, one run of most tests. VM timing is noisy.
