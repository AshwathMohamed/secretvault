# Design

```
sv_alloc : alloc_page -> fill(page) [still mapped, no second copy] -> set_memory_np(direct-map alias)
sv_access: lock -> (dead? -ENODEV) -> set_memory_p -> callback(secret) -> set_memory_np -> unlock
sv_free  : lock -> dead=true -> unlock -> drop owner reference
release  : (last reference gone) set_memory_p -> memzero_explicit -> free page -> kfree
```

## Lifetime model
- `struct sv_secret` is reference counted (`kref`). `sv_alloc()` hands the caller one reference.
- Any other user takes `sv_get()` before the owner may call `sv_free()`, and calls `sv_put()` when done.
- `sv_free()` marks the object dead under its mutex, so later `sv_access()` calls fail with `-ENODEV` instead of
  touching freed memory; the page and struct are released only when the last reference is dropped, so no code
  ever frees an object that another thread is still inside.
- The `stress` command races N kernel threads (each holding its own reference) against `sv_free()`; the expected
  outcomes are `ok` and `freed_under_us`, never errors, crashes or KASAN reports.

## API hardening
Exported functions reject NULL/invalid arguments (`-EINVAL`): `sv_alloc` (output pointer), `sv_access` (secret,
callback), `sv_hide_page`/`sv_unhide_page`, `sv_dmap_state`, `sv_scan_aliases`.

## Scanner and the two findings
`sv_scan_aliases()` walks the upper-half PGD entries of `init_mm` and reports two numbers for a pfn:
1. `present`: present mappings covering the pfn. **Intended protection** against a Meltdown-US-style load.
2. `residual_np`: non-present PTEs that still contain the pfn. **Informational**: relevant to L1TF-class attacks,
   not defended here. In this design at least one is expected after hiding.
`check` prints them on separate lines (`PRESENT_ALIAS_CHECK`, `RESIDUAL_NP_INFO`). Only the first can fail a test.
A positive control (`control`) first proves the scanner can see a normal page's mapping, and test T04c proves it can
see a stale non-present entry, so "0 present aliases" is not just a broken scanner.

## Why the window is shared and long
`set_memory_*` takes locks, may allocate (huge-page split) and sends TLB IPIs, so it cannot run with interrupts
disabled. The window is therefore a sleepable, system-wide re-presentation of the direct-map entry. This is the main
limitation and is measured by T07. A CPU-private mapping would fix it but needs in-tree kernel changes and is
**future work outside this project's scope**.
