# ADR-009: Privilege Concert (single admin auth per user action)

## Status

Accepted

## Context

Multi-step privileged workflows (first-run setup, host hardenings, Custom/Integrity
scans with several rootkit/audit packs) previously issued **one polkit prompt per
helper call**. Long malware scans before integrity packs made later prompts easy to
miss. Expanding passwordless YES to scanners was rejected (durable root for malware
tools under the same UID). `auth_admin_keep` on generic `run` is timing-dependent and
weak for variable argv.

## Decision

**Privilege Concert:** userspace builds a declarative `PrivilegePlan` (recipe, step
labels, helper argv). The UI/CLI discloses the plan, then one `pkexec oyst-helper
<argv1>` runs an allowlisted recipe inside a shared concert engine.

| argv1 (polkit message) | Recipe | Engine |
|------------------------|--------|--------|
| `setup-concert` | `setup` | shared |
| `setup-harden` | `harden` | shared |
| `scan-concert` | `scan-privileged` | shared |
| `update-concert` | `update-all` | shared |
| `rkhunter-whitelist` | `resolve-rkhunter` (userspace) | same argv1; concert façade + preflight |

Rules:

- Concerts always use `auth_admin` (not KEEP). Passwordless YES stays limited to
  `systemctl-up` + `maldet-config`.
- No free-form shell; reuse existing validators / sealed install / trusted binaries.
- Unknown recipe or step id fails closed.
- Scan execution: privileged packs first (one concert), then clamav/maldet locally.
- New multi-step elevated features add a **recipe + step validators**, not an ad-hoc
  pkexec loop.

Userspace API: `oyst_core/privilege/` (`PrivilegePlan`, recipes, `preflight_*`,
`run_privilege_concert`). Helper: `helper_concert` + recipe modules. Policy version
**12** adds `update-concert` (v11 added `scan-concert`).

**Phase 2 (Resolve):** rkhunter Resolve open / row Resolve use recipe
`resolve-rkhunter` for disclosure and `run_privilege_concert`, but keep existing
polkit action `rkhunter-whitelist` + `set-many` (no new argv1). Batch `services-up`
is deferred (no multi-toggle product surface; passwordless grant covers common
AV start/enable).

**Bulk façade (Install All / Update all):** GUI bulk actions disclose a
priority-ordered `PrivilegePlan` (required → recommended → optional → harden →
propupd). Lite **Install All** reuses `setup-concert` via `setup.run` with an
explicit `packs` list. Full mode uses `runtime.install` (no pack = `--all`)
without polkit. **Update all** uses `update-concert` for official package upgrades
plus `rkhunter --update` / `--propupd` in one `auth_admin` prompt; AUR upgrades stay
user-mode (paru/yay); signature refreshes (freshclam/fangfrisch/maldet) run locally
after the concert. Harden / Auto-Install recipe toggles feed the same concert argv
builders.

## Consequences

- Operators must reinstall the helper after upgrade (`sudo oyst-cli
  install-privileged-helper`) for policy **v12**.
- GUI/CLI must show plan summary before elevation when privileged steps exist.
- Single-step actions (one firewall ensure, one service toggle) may stay as direct
  argv1.

## Rejected alternatives

- Expanding YES to scanner `run` / `run-sealed`
- Storing sudo passwords in oysterAV
- Preflight `pkexec true` alone without KEEP or concert
- `auth_admin_keep` on `run` as the primary fix
