# Threat model

**Attacker:** unprivileged local user code on the same machine (or VM).
**Target:** selected kernel secrets held in vault pages.
**Defended property:** while the vault is closed, the secret's physical page has no *present* virtual mapping in the
kernel page tables, so a Meltdown-US-style transient load has no translation to forward data from.

**Not defended**
- L1TF: non-present PTEs still contain the pfn (reported, not fixed).
- MDS family, Spectre v1/v2, other transient-execution bugs.
- Data in registers, stack or any copy the callback makes.
- Root, DMA attackers, hypervisor, physical access, `/dev/mem` on kernels without lockdown.
- The access window (shared mapping, see LIMITATIONS 1).

**Claim:** removes the persistent kernel mapping of chosen secrets; exposure exists only during explicit windows.
**Non-claim:** this does not fix Meltdown.

**Evidence the repo produces:** scanner controls (T03, T04c), present-alias check (T04b/T06b), `/proc/kcore` probe with a
positive control (T05/T07), lifetime stress (T12), overhead numbers (T08) and KPTI baseline (T10).
Running a Meltdown proof-of-concept (T11) is deferred.
