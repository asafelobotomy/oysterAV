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
`oysterav/` must stay ≤ 400 lines. Existing over-limit files are grandfathered
with frozen ceilings in [`scripts/loc_allowlist.json`](scripts/loc_allowlist.json)
(they must not grow; remove an entry once split to ≤400). Enforced by
`uv run python scripts/check_loc.py` in `check.sh` and CI.

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
**Intentional CLI-first remainder** (no full GUI DSL): setup check/reset, firewall rule
DSL, fail2ban jail control, deep pack CLIs. Helper install and auth grant/revoke are
GUI Install button + passwordless toggle via Polkit RPC (`helper.install` /
`auth.grant_service_lifecycle`). Catalogued in
[docs/cli/gui-contract.md](docs/cli/gui-contract.md); parity enforced by
`tests/test_cli/test_gui_cli_parity.py`.

See also [docs/adr/007-gui-remapping-phase.md](docs/adr/007-gui-remapping-phase.md).

## Releasing

Bump [`VERSION`](VERSION), run `python scripts/sync_version.py`, push to `main`.
See [docs/packaging/release.md](docs/packaging/release.md).
