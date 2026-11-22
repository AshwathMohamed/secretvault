# Changes after review
| # | Finding | Fix |
|---|---|---|
| 1 | `sv_free()` unlocked then freed while another caller could still use the object | `kref` lifetime. `sv_free()` marks dead + drops the owner ref; page/struct freed only on last `sv_put()`. New `stress` test races access against free |
| 2 | Exported API did not validate arguments | `-EINVAL` on NULL `out`/`s`/`fn`/pointers in `sv_alloc`, `sv_access`, hide/unhide, `sv_dmap_state`, `sv_scan_aliases`; `-ENODEV` after free |
| 3 | PASS ignored `residual_np` | `check` prints `PRESENT_ALIAS_CHECK` and `RESIDUAL_NP_INFO` separately; T04c verifies the scanner sees the stale PTE |
| 4 | `kcore_probe.py` used `p_memsz` instead of `p_filesz`; `0` words could hide a failed read | Correct field; distinct statuses/exit codes (FULL_READ, PARTIAL_READ, UNREADABLE, SEGMENT_NOT_FOUND, ERROR); T05 only counts if the T07 positive control passed; parser self-tested with a synthetic ELF |
| 5 | Built against 6.8 but guest runs 7.0.0-43 | Builds clean against both 6.8.0-151 and 7.0.0-43-generic headers; `run_all.sh` prints kernel + header status and stops if headers are missing; README has a "Tested on" table that must be completed by a real run |
| 6 | `run_all.sh` hung at T07: a bare `wait` also waited for the `tee` process created by the script's own output redirection | `wait` now waits only for the background `hold` process (`HOLD_PID`) |
| 7 | dmesg check reported a false failure: `grep -i BUG` matched the word "debug" in the module's own load message | case-sensitive `BUG:` |
| - | T11 (Meltdown PoC) | Deferred / removed from the default plan |
| - | v2 private window | Moved out of scope (future work) |
