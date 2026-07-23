# Agent guide — oysterAV

Linux security orchestrator: `oyst-cli` (CLI/RPC backend) + thin GTK4 GUI (`oysterav`).
Repo: https://github.com/asafelobotomy/oysterAV

Shared logic lives in `oyst_core`. See ADRs under [`docs/adr/`](docs/adr/README.md)
(index of Accepted / Superseded decisions).

## Prerequisites

- Python ≥ 3.12 and [uv](https://docs.astral.sh/uv/)
- Host GTK4 / libadwaita introspection for the GUI (`uv sync --extra gui`)

## Setup

```bash
uv sync --extra all          # recommended for agents (dev + gui)
# or:
uv sync --extra dev          # CLI + tests + ruff/mypy
uv sync --extra gui --extra dev
```

There is no `.env` file. Secrets are local XDG paths (not committed):

- `~/.local/share/oysterav/oyst.token` (RPC, mode 0600)
- `~/.local/share/oysterav/oyst.sock`

Do not commit those paths or any credentials.

## Validate changes

```bash
./scripts/check.sh           # version + LOC + ruff + mypy + pytest with coverage (CI triad)
./scripts/check.sh --quick   # faster core/cli pytest without coverage
./scripts/check.sh --format  # also enforce ruff format
```

**400-line hard limit:** production Python under `oyst_core/`, `oyst_cli/`, and
`oysterav/` must stay ≤ 400 lines. Ceilings for intentional exceptions live in
[`scripts/loc_allowlist.json`](scripts/loc_allowlist.json) (empty when none).
Enforced by `uv run python scripts/check_loc.py` in `check.sh` and CI.

Coverage: `pytest` measures `oyst_core` + `oyst_cli` (branch on) with
`fail_under` in [pyproject.toml](pyproject.toml). `oysterav` is **not** in the
coverage source list — GUI quality is enforced by parity +
`oysterav/gui/rpc_actions.py` unit tests, not line %.

| Gate | What it proves |
|------|----------------|
| `scripts/check_loc.py` | Production files ≤400 lines (or within frozen allowlist ceiling) |
| `test_gui_cli_parity` / `test_rpc_parity` | Every GUI/`RpcServer` method has a CLI command (existence) |
| `tests/test_core/test_rpc_actions.py` | ADR-007 GUI actions call the right `OystClient` methods |
| Unit tests under `tests/test_core/` | Behavioral logic (mocks; no real scanners) |
| CLI smoke / `--help` | Command registration and confirm gates |

Scoped loops:

```bash
uv run ruff check oyst_core/path/to/file.py
uv run ruff format oyst_core/path/to/file.py
uv run mypy oyst_core/path/to/file.py
uv run pytest tests/test_core/test_foo.py -q --no-cov
```

GUI tests need PyGObject (`gi`). Without `--extra gui`, GUI-dependent tests are skipped.

## ADR-005 / ADR-007 (GUI remapping)

ADR-005 (CLI production freeze) is **superseded** by [ADR-007](docs/adr/007-gui-remapping-phase.md).
New GUI surfaces are allowed when matching CLI/RPC exists (or lands in the same PR).
[ADR-002](docs/adr/002-cli-first-gui-is-client.md) still requires `OystClient` only — no security subprocesses in `oysterav/`.
Living map: [docs/cli/gui-contract.md](docs/cli/gui-contract.md).

## Architecture notes

- GUI talks to security tools only via `OystClient` (Unix JSON-RPC or in-process fallback). CI greps for forbidden GUI subprocesses.
- Privileged ops go through polkit `oyst-helper` (`oyst-cli install-privileged-helper`). No raw `pkexec bash` fallback.
- **Privilege Concert** ([ADR-009](docs/adr/009-privilege-concert.md)): userspace `oyst_core/privilege/` builds a `PrivilegePlan`; one `auth_admin` polkit prompt runs allowlisted recipes via helper argv1 `setup-concert` / `setup-harden` / `scan-concert` (plus Resolve façade on `rkhunter-whitelist`). Reinstall the helper after policy bumps.
- Runtime modes: **full** (tools under `~/.local/share/oysterav/runtime/`) vs **lite** (host packages). Set with `oyst-cli config set runtime.mode full|lite`.
- ClamAV on-access **blocking** is host co-control (never wholesale `clamd.conf` rewrite): [ADR-008](docs/adr/008-clamav-host-cocontrol.md), [operator guide](docs/user-guide/clamonacc-prevention.md).

## Health / debug

```bash
uv run oyst-cli doctor --json
uv run oyst-cli status assess --json
uv run oyst-cli runtime status --json
uv run oyst-cli serve --foreground   # RPC for GUI
uv run oysterav                      # GUI
```

## GUI remapping (ADR-007)

Waves 1–3 and limited Wave 4 (firewall status + fail2ban unban) are shipped.
**Permanent CLI-first remainder** (no full GUI DSL): setup check/reset, firewall rule
DSL, fail2ban jail control, deep pack CLIs. Helper install and auth grant/revoke are
GUI Install button + passwordless toggle via Polkit RPC (`helper.install` /
`auth.grant_service_lifecycle`). Catalogued in
[docs/cli/gui-contract.md](docs/cli/gui-contract.md); parity enforced by
`tests/test_cli/test_gui_cli_parity.py`.

ADR-008 Phase 4–4.1 host co-control (`clamonacc ensure-fdpass` /
`ensure-prevention`, `virusevent ensure`, `clamav ensure-disable-cache`) are
CLI/RPC + thin Real-time GUI (DisableCache is CLI/health-driven).

See also [docs/adr/007-gui-remapping-phase.md](docs/adr/007-gui-remapping-phase.md).

## Releasing

Bump [`VERSION`](VERSION), run `python scripts/sync_version.py`, push to `main`.
See [docs/packaging/release.md](docs/packaging/release.md).

## Learned User Preferences

- Prefer CLI/RPC surfaces first for new features; wire the GUI only after matching commands exist.
- Prefer a detailed plan before implementing large multi-surface or security-sensitive changes; for audits, deliver findings-only reports first and remediate only after a separate approved plan.
- Prefer recognizing host-installed tools as installed (system vs private runtime) without forcing a pack reinstall.
- Prefer a single password/auth prompt at the start of each user-initiated action (Privilege Concert), including multi-pack scans, hardenings, Update all, and bulk resolve/quarantine—not mid-flow or per-item prompts; order disclosed steps by priority.
- Prefer Settings options that autosave; avoid redundant Save buttons when individual controls already persist.
- Prefer a lean GUI that does not duplicate Settings controls onto Scan or other tabs; bulk Update/Apply/Install All actions should use one collapsible itemized checklist with per-item controls (no duplicate lists).
- Prefer distro-portable host integration over distro-specific one-offs.
- Prefer host co-control that works in concert with the host (surgical drop-ins / ensure-*); never wholesale override of host ClamAV or daemon config.
- Prefer first-run/setup wizard auto-application of safe surgical hardenings; leave path-scoped on-access prevention for Real-time after the user chooses paths.
- Prefer SSH-safe checks before enabling UFW/firewalld during setup/wizard flows.
- Prefer user-facing system and status messages without developer notes or internal implementation jargon.
- Prefer GUI chrome that keeps a stable default window size: primary pages (especially Scan) should fit without scrollbars, and optional UI (news ticker) or post-action refreshes must not change status-bar or window height.

## Learned Workspace Facts

- oysterAV is a from-scratch successor to deprecated xanadOS Search & Destroy (https://github.com/asafelobotomy/xanadOS-Search_Destroy).
- Repository license is GPLv3.
- Default GUI themeing target is Gruvbox Dark Hard via a shared theme/color library.
- Status-bar pack/service update notices take priority over the security-news ticker.
- Security-news ticker freshness is configurable in Settings (7/14/30 days; default 14).
- Privileged-helper install refuses to embed a user-writable oysterAV checkout; `oyst_core` must live under a root-owned prefix (distro package or root install), which matters on externally-managed Python distros (e.g. Arch/CachyOS).
- Privilege Concert ([ADR-009](docs/adr/009-privilege-concert.md)) is the unified single-admin-auth-per-user-action model for privileged multi-step flows (scans, setup hardenings, Update all / update-concert, resolve, bulk install).
