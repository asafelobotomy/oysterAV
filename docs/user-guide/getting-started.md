# Getting Started with oysterAV

## Prerequisites

- Python ≥ 3.12 and [uv](https://docs.astral.sh/uv/)
- Host GTK4 / libadwaita for the optional GUI

## Install oyst-cli

```bash
uv sync --extra all
# or: uv sync --extra dev
uv run oyst-cli doctor
```

## First run (recommended)

Run the guided setup wizard equivalent:

```bash
uv run oyst-cli setup run --json
uv run oyst-cli status assess --json
```

First bootstrap can take several minutes (network + signature updates). Soft-failed steps (schedule timer, linger) are non-fatal; fix later with `oyst-cli schedule apply`.

Or step-by-step:

```bash
uv run oyst-cli maintenance bootstrap --skip-lynis
uv run oyst-cli scan ~/Downloads --profile quick --json
```

## After system updates

```bash
uv run oyst-cli maintenance post-update
```

## Pack runtime

Full mode (default) bundles tools privately:

```bash
uv run oyst-cli runtime bootstrap --json
```

Or manually:

```bash
uv run oyst-cli runtime install --all
uv run oyst-cli runtime update
```

Lite mode uses host packages only — see [packaging/lite/README.md](../../packaging/lite/README.md).

## Recommended desktop schedule

```bash
uv run oyst-cli config set schedule.profile quick
uv run oyst-cli config set schedule.backend inherit
uv run oyst-cli config set scan.backend auto
uv run oyst-cli config set schedule.frequency daily
uv run oyst-cli config set schedule.time 02:00
uv run oyst-cli schedule apply
uv run oyst-cli clamav clamd ensure
```

Keep signatures fresh with `oyst-cli updates apply` or `maintenance post-update`
(freshclam → fangfrisch → rkhunter propupd). Leave `quarantine.auto` off until you
are comfortable reviewing findings first.

Scan tuning keys (`scan.max_filesize`, `fangfrisch.providers`, `clamav.ignore_sigs`,
…) are documented in [docs/cli/pack-commands.md](../cli/pack-commands.md#scan-tuning-configtoml).

## Pack tiers

| Tier | Packs |
|------|-------|
| Required | clamav, freshclam |
| Recommended | rkhunter, chkrootkit, lynis, clamonacc, firewall |
| Optional | maldet, unhide, fail2ban, fangfrisch |

Run `oyst-cli doctor` for distro-specific install commands.

## Shell completion

```bash
# bash
eval "$(_OYST_CLI_COMPLETE=bash_source oyst-cli)"

# zsh
eval "$(_OYST_CLI_COMPLETE=zsh_source oyst-cli)"
```

## CLI reference

See [docs/cli/reference.md](../cli/reference.md) for the full command tree.

## GUI (remapping phase — ADR-007)

```bash
uv sync --extra gui --extra dev
uv run oysterav
```

The GUI uses `OystClient` only — it never calls security tools directly ([ADR-002](../adr/002-cli-first-gui-is-client.md)).
New GUI features follow the remapping waves in [ADR-007](../adr/007-gui-remapping-phase.md) (CLI/RPC first).
