# Limitations (honest list)
1. The access window re-presents the **shared** direct-map entry: any CPU can reach the page while it is open (T07).
2. A hidden page keeps a non-present PTE holding its pfn: **L1TF-class** leaks are not addressed (reported as RESIDUAL_NP_INFO).
3. MDS, Spectre and other transient-execution leaks are not addressed; data in registers/buffers is out of reach.
4. Hiding splits a direct-map huge page into 4K pages; the split is not undone by this module (TLB/memory cost).
5. One page per secret; no pooling.
6. The callback is trusted: it can copy the secret into normal memory. Nothing enforces otherwise.
7. Not excluded from crash dumps, hibernation images, kprobes/BPF, or `/dev/mem` when lockdown is off.
8. The scanner is lockless/racy and covers only the kernel half of `init_mm`.
9. Uses kprobe+kallsyms to reach unexported symbols; breaks under kernel lockdown or future hardening.
10. x86_64 only. Compiled against Ubuntu 6.8 and 7.0.0-43 headers; runtime must be validated on your guest kernel.
11. On CPUs "Not affected" by Meltdown, only the structural property can be shown, not a blocked leak.
12. Lifetime rules are by convention for external callers: take `sv_get()` before sharing a pointer, call `sv_free()` once.
