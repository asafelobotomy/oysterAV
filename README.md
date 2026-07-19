# oysterAV

Linux security orchestrator: **oyst-cli** (CLI-first backend) + **oysterAV** (GTK4 GUI client).

## Prerequisites

- Python ≥ 3.12
- [uv](https://docs.astral.sh/uv/)
- For the GUI: system GTK4 + libadwaita (PyGObject introspection)

## Quick start

```bash
uv sync --extra all
# or: uv sync --extra dev
uv run oyst-cli setup run --json
uv run oyst-cli status assess --json
uv run oyst-cli scan ~/Downloads --json
```

`setup run` may take several minutes on a cold machine (signature updates / pack installs). Schedule or rkhunter steps can soft-fail; check `--json` step results.

Validate local changes:

```bash
./scripts/check.sh --quick
```

See [docs/cli/reference.md](docs/cli/reference.md) and [ADR-007](docs/adr/007-gui-remapping-phase.md) (GUI remapping; CLI/RPC first).

## GUI (optional; remapping phase)

```bash
uv sync --extra gui --extra dev
uv run oysterav
```

The GUI uses `OystClient` only — it never calls security tools directly ([ADR-002](docs/adr/002-cli-first-gui-is-client.md)).
New GUI features follow the remapping waves in [ADR-007](docs/adr/007-gui-remapping-phase.md).

## Architecture

- `oyst_core` — pack adapters, orchestrator, quarantine, serve RPC
- `oyst_cli` — full CLI (`oyst-cli`)
- `oysterav` — thin GTK4 client via `OystClient` (no direct security subprocess calls)

## Pack runtime (Full mode, default)

Full mode installs vendored upstream tools to `~/.local/share/oysterav/runtime/` and manages ClamAV signatures locally:

```bash
uv run oyst-cli runtime status
uv run oyst-cli runtime install --all
uv run oyst-cli runtime update   # ClamAV CDIFF signature updates
```

Use **Lite mode** for system-package-only installs (see [packaging/lite/README.md](packaging/lite/README.md)):

```bash
uv run oyst-cli config set runtime.mode lite
```

## System packs (Lite mode)

| Tier | Packs |
|------|-------|
| Required | clamav, freshclam |
| Recommended | rkhunter, chkrootkit, lynis, clamonacc, firewall |
| Optional | maldet, unhide, fail2ban, fangfrisch |

Install ClamAV on your host before scanning:

```bash
# Debian/Ubuntu
sudo apt install clamav clamav-daemon rkhunter chkrootkit lynis

# Arch
sudo pacman -S clamav rkhunter chkrootkit lynis

# Fedora
sudo dnf install clamav clamav-update rkhunter chkrootkit lynis
```

## Health / debug

```bash
uv run oyst-cli doctor --json
uv run oyst-cli status assess --json
uv run oyst-cli serve --foreground
```

## Flatpak

See [packaging/oysterav/flatpak/README.md](packaging/oysterav/flatpak/README.md). Full mode stores runtime under `$HOME/.local/share/oysterav/runtime`.

## License

GPL-3.0-or-later
