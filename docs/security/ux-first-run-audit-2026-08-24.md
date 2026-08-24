# First-run / UX audit — 2026-08-24

**Status:** All remediation waves landed (2026-08-24).  
**Canvas:** `ux-first-run-audit-2026-08-24.canvas.tsx`  
**Trigger:** Empty host ClamAV DB + skipped wizard on AUR “first launch.”

## Already fixed before this audit

- Host CVD before clamd enable (`ensure_host_daily_signatures` / `enable-stack` / harden-clamd)
- Wizard reopens when host daily signatures missing (`assess_setup.missing_signatures`)
- `services.set(clamd)` / `ClamAVPack.start` → enable-stack
- firewalld SSH-before-enable (prior F-01)

## Remediations (this change set)

| Wave | IDs | Status |
|------|-----|--------|
| 1 Completion honesty | UX-16/17/18/19 | Fixed |
| 2 Wizard truth | UX-03/10/11/12/20 | Fixed |
| 3 Ordering | ORD-01–08, UX-06/26 | Fixed |
| 4 First-run + host | UX-01/02/04/08/13/15/23/24/25/29 | Fixed |

### Critical / High highlights

| ID | Fix |
|----|-----|
| UX-01 | `setup.completed_install` fingerprint; assess `install_mismatch` |
| UX-02 | `helper_missing` in `assess_setup` + wizard copy |
| UX-16 | packs-gate no longer auto-sets `required_packs` skip |
| UX-17 | `bootstrap_critical_ok` (freshclam gate) |
| UX-18 | full bootstrap overall OK = all non-skipped steps |
| UX-19/24/25 | `_BLOCKS_COMPLETE` for security steps + linger/firewall |
| ORD-01 | `helper_harden_reprobe` after pack install in concert |
| ORD-02 | `clamonacc.start` → shared `_enable_stack` |
| ORD-03/08/26 | `wait_for_clamd_ready`; gate later Clam harden steps |
| ORD-04/05 | signature preflight on restart/fdpass |
| ORD-06 | prevention chains best-effort fdpass |
| ORD-07 | fail2ban jail-start enable-nows daemon first |
| UX-06 | early bootstrap when no pack installs |
| UX-10/11 | Auto-Install warnings + ran-flags from real OK steps |
| UX-23/15 | Services helper refuse dialog |
| UX-29 | Maintenance “Run setup wizard” resets first-run then opens |

### Intentionally light / deferred

| ID | Note |
|----|------|
| UX-05 | Continue-anyway still honors skip by design; Dashboard CTA remains |
| UX-07 | Page order unchanged; harden still downloads CVD |
| UX-09 | Default `runtime.mode=full` unchanged (product default) |
| UX-14 | Fallback string kept when signatures present but process missing |
| UX-21 | Host CVD gate kept for host clamd (correct for Arch) |
| UX-22 | Mitigated by CVD-before-enable + hard complete blockers |
| ORD-09/10/11/12 | Low/Info — doctor warn / policy / display order |

## Validation

```bash
uv run ruff check …
uv run mypy …
uv run pytest tests/test_cli/test_setup_workflow.py tests/test_core/test_helper_*.py \
  tests/test_core/test_clamd_ensure.py tests/test_gui/test_setup_wizard.py -q --no-cov
uv run python scripts/check_loc.py
```
