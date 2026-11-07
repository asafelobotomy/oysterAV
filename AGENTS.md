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
./scripts/check.sh           # version + LOC + ruff + mypy + pytest + security gates
./scripts/check.sh --quick   # faster core/cli/security pytest (no global coverage)
./scripts/check.sh --format  # also enforce ruff format
```

Security gates (`pytest -m security`, module coverage ≥85%, Bandit, pip-audit):
[`docs/security/test-gates.md`](docs/security/test-gates.md).

**400-line hard limit:** production Python under `oyst_core/`, `oyst_cli/`, and
`oysterav/` must stay ≤ 400 lines. Ceilings for intentional exceptions live in
[`scripts/loc_allowlist.json`](scripts/loc_allowlist.json) (empty when none).
Enforced by `uv run python scripts/check_loc.py` in `check.sh` and CI.

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

- GUI talks to security tools only via `OystClient` over Unix JSON-RPC to a separate `oyst-cli serve` process it auto-spawns (`local_fallback=False`; no in-process dispatch). The CLI keeps a same-UID in-process fallback. CI greps for forbidden GUI subprocesses.
- Privileged ops go through polkit `oyst-helper` (`oyst-cli install-privileged-helper`). No raw `pkexec bash` fallback.
- **Privilege Concert** ([ADR-009](docs/adr/009-privilege-concert.md)): userspace `oyst_core/privilege/` builds a `PrivilegePlan`; one `auth_admin` polkit prompt runs allowlisted recipes via helper argv1 `setup-concert` / `setup-harden` / `scan-concert` (plus Resolve façade on `rkhunter-whitelist`). Reinstall the helper after policy bumps.
- Runtime modes: **full** (tools under `~/.local/share/oysterav/runtime/`) vs **lite** (host packages). Set with `oyst-cli config set runtime.mode full|lite`.
- ClamAV on-access **blocking** is host co-control (never wholesale `clamd.conf` rewrite): [ADR-008](docs/adr/008-clamav-host-cocontrol.md), [operator guide](docs/user-guide/clamonacc-prevention.md).

## Health / debug

## More detail (read on demand, under `docs/agents/`)

- `gates-and-coverage.md` — coverage scope and what each gate proves.
- `gui-remapping.md` — ADR-007 status: what is CLI-only, what is wired to the GUI.
- `debug-and-release.md` — `doctor`/`status`/`serve` debug commands; release steps (bump `VERSION`, `scripts/sync_version.py`).
- `learned-preferences-and-facts.md` — recorded user preferences (CLI-first, single auth prompt, lean GUI, autosave settings, ...) and workspace facts; read before GUI/UX or privileged-flow design.
