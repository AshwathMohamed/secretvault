#  secretvault

**What if, instead of hiding the whole kernel from user programs, I hide only the secrets?**

This is my student project on Linux kernel memory protection. It's a small kernel module plus a test suite, and it
tries one idea: hide only the important kernel data (like encryption keys), instead of what KPTI does.

It works in my VM, and it has real problems. I list them honestly below. 

---

##  Where the idea came from

I was learning about the **Meltdown** bug. A normal program isn't allowed to read kernel memory, but the CPU
*speculatively* does the read anyway before it checks permissions. The result gets thrown away, but it leaves
tiny traces in the cache, and an attacker can read those traces and recover the kernel data.

Linux fixed this with **KPTI** (Kernel Page-Table Isolation). While a user program runs, most of the kernel is
removed from its page tables, so there is nothing for the CPU to speculatively read. It works, but every
system call has to switch page tables, so everything gets a bit slower.

So I asked myself: **KPTI hides *everything* all the time. What if I hide only the few things that really matter,
and pay the cost only when I touch them?**

That's the idea behind this project.

##  How it works

```
 alloc  ->  fill the page with the secret  ->  remove it from the kernel's direct map
 use    ->  put the mapping back  ->  run the callback  ->  remove it again
 free   ->  put the mapping back  ->  wipe the page with zeros  ->  give it back
```

- `sv_alloc()` allocates one page and fills it **before** hiding it, so the secret never exists in a second buffer.
- `sv_access(secret, callback)` opens a short **window**, runs your function on the secret, then closes the window.
  I made it callback-based so the code never hands out a pointer to the secret.
- `sv_free()` wipes the page and releases it. The object is reference counted, so a free can't pull the memory out
  from under someone who is still using it.
- A **page-table scanner** walks the kernel page tables and checks whether *any* mapping of the secret's page is
  still present. I didn't want to just assume it was hidden.

##  Does it work? (my VM, Ubuntu, kernel 7.0.0-43)

The test suite gave **21 passed, 0 failed, 0 inconclusive**. Highlights:

| What I checked | What I saw |
|---|---|
| Secret hidden while the window is closed | no present mapping, and `/proc/kcore` can't see it  |
| Window open | `/proc/kcore` **can** read all 512 pattern words (more on this below) |
| Cost of one window | about **183 µs** vs about 0.4 µs for a normal page alloc/free (roughly 440x slower ) |
| KPTI cost for comparison | about **73 ns per syscall** (roughly 12%) |
| Break-even | one window costs about the same as the KPTI tax on ~2,500 syscalls |

Be careful with that last row. It is a **cost** comparison, **not** a protection comparison. KPTI protects *all*
kernel memory. Mine protects only the pages I choose, and only while the window is closed.

Full numbers are in `docs/RESULTS.md`, and the raw logs are in `docs/logs/`.

##  What I couldn't do (the honest list)

1. **The window is not private.** While it's open, the page is visible in the *shared* kernel page tables, so any
   CPU could read it. My own test (T07) proves this on purpose. A CPU-private mapping would fix it, but that needs
   kernel changes, not just a module. That was beyond what I could do here.
2. **A leftover entry stays behind.** Hiding a page clears its "present" bit, but the entry still contains the page
   number. That matters for **L1TF**-type attacks, which I don't defend against. The scanner reports it so I can't
   pretend it isn't there.
3. **Only Meltdown-style reads are in scope.** I do nothing for MDS, Spectre and similar bugs, and nothing for data
   sitting in registers.
4. **It's slow.** About 183 µs per window. It's only sensible for rarely used, high-value secrets. Part of that cost
   is probably my VM (TLB-flush interrupts are expensive in a VM), but I didn't measure the cause.
5. **One page per secret, and the huge page gets split.** Hiding one page splits a 2 MB direct-map entry into
   4 KB entries, and I don't merge it back.
6. **The callback is trusted.** It could copy the secret somewhere visible, and nothing stops it.
7. **Not hidden from everything.** No protection against crash dumps, hibernation images or kprobes/BPF.
8. **The module uses a hack.** It finds a few unexported kernel functions with a kprobe trick. That's okay for a
   research VM and a bad idea for anything real.
9. **Thin testing.** One VM, one kernel, mostly one run per test, and no KASAN kernel. In the stress test about
   99% of the accesses just got "already freed" back, so the race is only lightly exercised. `errors=0` is
   evidence, not proof.
10. **I did not run a real Meltdown attack.** My CPU does report as vulnerable ("Mitigation: PTI"), so a proof of
    concept is possible later. For now I only prove the *structure* (no mapping), not a blocked leak.

## ▶ Try it yourself (x86_64 Linux, **inside a VM, with a snapshot!**)

```bash
scripts/setup_vm.sh        # build tools + headers for your running kernel
scripts/check_cpu.sh       # see your Meltdown/L1TF/MDS status
make                       # builds the module and the syscall benchmark
sudo tests/run_all.sh      # runs everything, log goes to results/
```

You need `CONFIG_KPROBES`, `CONFIG_DEBUG_FS` and `CONFIG_PROC_KCORE`. Turn off Secure Boot and module signing in
the VM, because the module is unsigned. Poke at it by hand:

```bash
sudo insmod module/secretvault.ko
D=/sys/kernel/debug/secretvault
echo alloc     | sudo tee $D/ctl; sudo cat $D/result
echo "check 0" | sudo tee $D/ctl; sudo cat $D/result
```

Commands: `alloc`, `free <id>`, `check <id>`, `access <id>`, `hold <id> <ms>`, `control`, `stress <threads> <iters>`,
`bench <n>`, `list`. Note that `hold` locks up the command interface for up to 60 s, and the debugfs files print
raw kernel addresses (root only).

 `bench/pti_compare.sh` edits GRUB and reboots your VM twice. Use it on Ubuntu with GRUB only, take a snapshot
first, and run `sudo bench/pti_compare.sh abort` to undo it.

##  What's where

```
module/   the kernel module (core, page-table scanner, debugfs test interface)
tests/    run_all.sh and kcore_probe.py
bench/    syscall benchmark + the pti on/off comparison script
scripts/  setup + CPU check (build_kernel.sh is optional)
docs/     threat model, design, limitations, test plan, my results, logs
```

##  Credits

I used an AI assistant to talk through the design and review the code. I ran everything and wrote everything in
my own VM, tested it, and fixed the bugs that showed up (they're listed in `docs/CHANGES.md`). It is **not** a real fix
for Meltdown. It's an experiment that taught me a lot about page tables, TLBs and how the kernel protects itself.

License: GPL-2.0 (kernel modules need it).
