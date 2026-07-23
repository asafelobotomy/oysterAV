# Full-surface audit — 2026-07-23

Findings-only review across CLI, RPC, GUI, privileged helper, host co-control,
Privilege Concert, docs/startup/validation gates. No code fixes in the audit
pass itself; remediation landed in Waves 1–3 (see status column).

**Threat model (security lane):** local same-UID malware or malicious content
under `$HOME` on a single-user wheel desktop. Out of scope: remote attackers
without a foothold; formal fuzzing / pen-test campaigns.

**Prior art:** [hardening-audit-2026-07.md](hardening-audit-2026-07.md) (helper
matrix, H-01…H-10, A-01…). This pass re-verifies residuals and expands to
product-surface parity + agent workflow scores.

## Executive verdict

No P0 privilege-escalation or auth-bypass regressions found. July hardenings
(H-01/H-02/A-01/A-02 symlink/sealed-argv/tarball SHA, RPC token+peercred,
auth-grant fail-closed TTL, surgical ClamAV co-control) still hold. Remediation
Waves 1–3 closed the open table: **`update-concert`** (C-01 / ADR-009 policy
**v12**), RPC long-timeout + gui-contract/CI/docs parity (S-01/P-*), concert
disclosure honesty (C-02…C-06), and H-05/H-06 env scrub + broader audit
redaction. Operators must reinstall the privileged helper after Wave 2.

## Severity table

| ID | Sev | Surface | Finding | Status |
|----|-----|---------|---------|--------|
| C-01 | P1 | Concert / updates | Update all: package `pkexec` then separate `rkhunter --update` / `--propupd` prompts; disclosure claims one auth | **Fixed** — `update-concert` (policy v12) |
| P-01 | P1 | docs | gui-contract “RPC methods used by GUI” omits many GUI-used methods | **Fixed** |
| P-02 | P1 | docs | Same summary lists RPCs the GUI never calls (`job.clear`, `schedule.install`, `runtime.update`, `clamonacc.start`/`stop`) | **Fixed** |
| S-01 | P2 | RPC | `LONG_RPC_METHODS` has `maintenance.post_update` (underscore); real method is `maintenance.post-update` → 30s client timeout | **Fixed** |
| C-02 | P2 | Concert / GUI | Setup/harden preflight builds plans with fake `--preview` argv (A-06 residual) | **Fixed** — `disclosure_only` |
| C-03 | P2 | Concert / GUI | Auto-Install preflight lists schedule as privileged though it runs after concert | **Fixed** — schedule as local step |
| C-04 | P2 | CLI / GUI | `setup run` has no `--confirm` / privilege preflight; GUI confirms first | **Fixed** — `--confirm` / `--dry-run` |
| P-03 | P2 | docs | gui-contract L218 `maintenance.post_update` vs canonical `maintenance.post-update` | **Fixed** |
| P-04 | P2 | tests / GUI | `request_updates_*` untested; `request_updates_check` unused | **Fixed** |
| P-05 | P2 | tests | Stale `GUI_CLIENT_TO_CLI` orphans (`clamonacc_start`/`stop`, `runtime_update`, …) | **Fixed** |
| P-06 | P2 | CI | CI GUI-subprocess `rg` narrower than `test_no_security_subprocess` | **Fixed** |
| H-05 | P2 | helper / runners | Non-pkexec `run_command` inherits full process env | **Fixed** — `command_scrubbed_env` |
| H-06 | P2 | audit | Path redaction covers `/home/…` only | **Fixed** — `/var/home`, `/run/user`, oysterAV tmp |
| A-06 | P2 | Concert | Empty-argv disclosure misuse | **Fixed** (via C-02) |
| A-07 | P2 | helper | Unknown `--pack=` silent drop | **Fixed** |
| S-02 | Info | RPC | `LONG_RPC_METHODS` dead entries (`lynis.audit`, `schedule.disable_linger`) | **Fixed** |
| C-05 | Info | Concert | Scan disclosure `job_id` ≠ orchestrator concert `job_id` | **Fixed** — threaded job_id |
| C-06 | Info | Concert | Userspace plan silently filters unknown pack names | **Fixed** — fail closed |
| C-07 | Info | docs | July audit still marks A-06/A-07 “Tracked”; `reference.md` says quarantine `add` needs no `--confirm` (CLI requires it) | **Fixed** |
| P-07 | Info | docs | Coverage blurb underspecifies `rpc_actions` scope | **Fixed** |
| P-08 | Info | docs | Host firewall CLI line omits `--json` | **Fixed** |
| D-01 | Info | docs | Completion / systemd examples assume `~/.local/bin/oyst-cli` after uv-only setup | **Fixed** |
| D-02 | Info | docs | Helper install root-owned/`--dev` constraints under-documented in README/getting-started | **Fixed** |
| U-01 | Info | GUI | Gtk markup warning: PreferencesGroup title `Appearance & desktop` unescaped `&` | **Fixed** |
| H-01 | P1 | helper | clamonacc list path symlink follow | **ok** (still fixed) |
| H-02 | P1 | helper | lynis `--profile` absolute path without fd checks | **ok** (still fixed) |
| H-03 | P1 | supply-chain | SECURITY.md / Scorecard / Dependabot / pinned Actions | **ok** |
| H-04 | P1 | RPC / config | XDG data dir `0700` | **ok** |
| H-07 | Info | auth-grant | YES scope = `systemctl-up` + `maldet-config` only; fail-closed TTL | **ok** |
| H-08 | Info | RPC | Token `0600`, peercred UID match, `compare_digest` | **ok** |
| H-09 | Info | co-control | Path-scoped prevention opt-in; surgical drop-ins | **ok** |
| H-10 | P0 | — | No confirmed priv-esc / auth bypass this pass | **ok** |
| A-01 | P1 | helper | `run-sealed` unvalidated argv | **ok** (still fixed) |
| A-02 | P1 | helper | `install-script` seal gaps | **ok** (still fixed) |
| G-01 | Info | gates | `./scripts/check.sh --quick` | **ok** (pass) |

## Per-surface notes

### CLI

- Command tree and pack CLIs remain the source of truth (ADR-002/007). Permanent
  CLI-first remainder (setup check/reset, firewall DSL, fail2ban jail control,
  deep pack CLIs) is documented without false GUI parity claims.
- Confirm gates match GUI for scan / resolve / quarantine / updates / `setup run`
  (`--confirm` or `--dry-run`).
- Quarantine `add` requires `--confirm` in CLI; reference docs match.

### RPC

- Schema v2 ↔ `HANDLERS` / `RPC_METHODS` ↔ `test_rpc_parity.RPC_TO_CLI` remain
  aligned; `LONG_RPC_METHODS` is a strict subset of `RPC_METHODS` (incl.
  `maintenance.post-update`).

### GUI

- ADR-002 isolation: no scanner/firewall/`pkexec` subprocess under `oysterav/`
  (CI + unit test aligned).
- Privilege confirm for Update all matches single `update-concert` elevation.

### Privileged helper / polkit

- argv1 matrix includes `update-concert` (policy **v12**). Reinstall helper after
  upgrade: `oyst-cli install-privileged-helper`.
- Userspace `run_command` / non-pkexec install paths use `command_scrubbed_env`
  (PATH + locale/TZ only).

### Privilege Concert (ADR-009)

- Scan / setup-concert / setup-harden / resolve / lite Install All / **Update all**:
  **one** `auth_admin` per user action when elevation is needed.

## Residual tracker vs July 2026 hardening audit

| Prior ID | July status | This pass / remediation |
|----------|-------------|-------------------------|
| H-01 | Fixed | Still fixed |
| H-02 | Fixed | Still fixed |
| H-03 | Fixed | Still fixed |
| H-04 | Fixed | Still fixed (`data_dir` chmod `0700`) |
| H-05 | Accepted residual | **Fixed** (Wave 3) |
| H-06 | Deferred | **Fixed** (Wave 3) |
| H-07…H-09 | OK / docs | OK |
| H-10 | None found | None found |
| A-01 | Fixed | Still fixed |
| A-02 | Fixed | Still fixed |
| A-06 | Tracked Phase 2 | **Fixed** (Wave 1 C-02) |
| A-07 | Tracked Phase 2 | **Fixed** |

## Appendix A — Gate smoke

```text
./scripts/check.sh --quick
# Re-run after remediation waves; expect green triad (version/LOC/ruff/mypy/pytest).
```

## Operator note

After Wave 2 helper/policy changes:

```bash
oyst-cli install-privileged-helper
```
