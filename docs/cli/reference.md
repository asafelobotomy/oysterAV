# oyst-cli Command Reference

Quick reference for internal production use. All commands support `-v` / `--verbose` on the root group.

## First run

```bash
oyst-cli setup check --json          # wizard gate: exit 1 if attention needed
oyst-cli setup status --json         # completion state + missing packs
oyst-cli setup run --json            # guided batch setup (wizard equivalent)
oyst-cli setup run --enable-linger   # also enable linger when schedule advises it
oyst-cli setup reset --confirm       # clear completion to re-run setup
oyst-cli status assess --json
```

Guided setup mirrors the GTK setup wizard: doctor → pack install → bootstrap → preferences → schedule → mark complete (only when steps succeed).

Flags:

- `--skip-packs` — skip pack installation
- `--skip-schedule` — skip timer install
- `--skip-bootstrap` — skip bootstrap steps
- `--confirm-aur` — auto-confirm AUR installs
- `--auto-quarantine` / `--no-auto-quarantine` — set auto-quarantine default (current config kept if omitted)
- `--enable-linger` — enable user lingering when schedule reports it off
- `--no-mark-complete` — run steps without setting `setup.completed`
- `--maintenance-only` — maintenance bootstrap without full runtime install

## Desktop (GUI autostart / tray)

```bash
oyst-cli desktop status --json
oyst-cli desktop install-autostart [--minimized]
oyst-cli desktop remove-autostart
oyst-cli config set ui.run_at_startup true   # also writes XDG autostart
oyst-cli config set ui.start_minimized true  # rewrites Exec --minimized if autostart on
oyst-cli config set ui.minimize_to_tray true
oysterav --minimized                         # start GUI hidden (tray)
```

Autostart file: `~/.config/autostart/io.github.asafelobotomy.OysterAV.desktop`.

## Health

```bash
oyst-cli status --json          # raw aggregate status
oyst-cli status assess --json   # severity, issues, recommended_actions
oyst-cli doctor --json
```

## Bootstrap roles

| Goal | Command |
|------|---------|
| Guided first-run (wizard equivalent) | `oyst-cli setup run` |
| Full private runtime + signatures + maintenance | `oyst-cli runtime bootstrap` |
| Signatures / rkhunter baseline only | `oyst-cli maintenance bootstrap` |

## Runtime (Full mode)

```bash
oyst-cli runtime status --json
oyst-cli runtime bootstrap --json [--progress]
oyst-cli runtime install --all [--progress]   # pack name or --all required
oyst-cli runtime install lynis [--progress]
oyst-cli runtime remove lynis --confirm [--progress]   # private runtime only
oyst-cli runtime update
oyst-cli packs install lynis [--progress]   # full mode → private runtime; lite → distro packages
```

## Scans

```bash
oyst-cli scan ~/Downloads --profile quick --json
oyst-cli scan / --profile integrity --json
oyst-cli history --limit 20 --json
oyst-cli history show <job_id> --json
```

Profiles: `quick`, `full`, `integrity`, `suite` (malware + rootkits then Lynis audit), `custom` (requires `--packs`).

## Quarantine

```bash
oyst-cli quarantine list --json
oyst-cli quarantine show <id>
oyst-cli quarantine restore <id> --confirm
oyst-cli quarantine restore <id> --dry-run
oyst-cli quarantine delete <id> --confirm
oyst-cli quarantine delete <id> --dry-run
oyst-cli quarantine verify --json
oyst-cli quarantine add <path>
```

Restore/delete require `--confirm` (or `--dry-run` to preview). `add` is additive and does not require confirmation.

## Packs

```bash
oyst-cli packs list --json
oyst-cli packs install clamav --confirm-aur
```

Per-pack groups: `clamav`, `freshclam`, `clamonacc`, `fangfrisch`, `rkhunter`, `chkrootkit`, `lynis`, `maldet`, `firewall`, `fail2ban`, `unhide`.

See [pack-commands.md](pack-commands.md) for upstream mapping and [gui-contract.md](gui-contract.md) for GUI→CLI feature parity.

### Privileged pack mutations

Mutating commands require polkit (`oyst-helper`) and are audit-logged:

```bash
oyst-cli clamav clamd ensure --json
oyst-cli fail2ban unban 192.0.2.1 --confirm --json
oyst-cli firewall ufw allow --port 22 --proto tcp --from 192.0.2.0/24 --dry-run
oyst-cli firewall ufw allow --port 22 --proto tcp --confirm --json
oyst-cli firewall ufw enable --confirm
oyst-cli lynis audit --scope container-host --json
oyst-cli maldet monitor status --json
oyst-cli rkhunter propupd --confirm --json
```

Use `--confirm` (or `--dry-run`) for UFW/firewalld rule mutations, UFW enable/disable/default, fail2ban unban/jail control/`reload --unban`, rkhunter propupd, rkhunter resolve, runtime remove, schedule disable, and path removes. Firewall enable checks for an SSH allow rule unless `--force-lockout-risk`.

## Schedule

Config-driven systemd user timer (`oyst-scan.timer`). Scan semantics live in `[schedule]` config; the timer only holds the calendar.

```bash
oyst-cli schedule show              # config + derived OnCalendar
oyst-cli schedule status --json     # config + live systemd state / next run
oyst-cli schedule set --profile quick --frequency daily --time 02:00 --enabled
oyst-cli schedule set --packs clamav,rkhunter --paths ~/Downloads --apply
oyst-cli schedule apply             # write/reload units from config
oyst-cli schedule run --json        # one scan from schedule config (timer target)
oyst-cli schedule enable            # set enabled + apply
oyst-cli schedule disable --confirm # set disabled + stop timer
oyst-cli schedule install --profile quick   # compat one-click (defaults + apply; smoke-test on)
oyst-cli schedule template          # print timer unit text
oyst-cli schedule linger --json
oyst-cli schedule enable-linger
```

Prefer `set` / `apply` / `enable` for structured control; `install` is the compat one-click path. Defaults for one-click: **daily at 02:00**, profile **quick**, packs/paths from the profile.

Config keys: `schedule.enabled`, `schedule.profile`, `schedule.packs`, `schedule.paths`, `schedule.frequency`, `schedule.time`, `schedule.weekday`, `schedule.on_calendar`, `schedule.persistent`, `schedule.quarantine`, `schedule.backend`.

## Config

```bash
oyst-cli config path [--json]
oyst-cli config get                  # dump full config (--json)
oyst-cli config get scan.profile
oyst-cli config set quarantine.auto true [--json]
oyst-cli config set scan.max_filesize 50M
oyst-cli config set fangfrisch.providers sanesecurity,urlhaus
oyst-cli config set clamav.ignore_sigs Sanesecurity.Spam.1
oyst-cli config set rkhunter.disable_tests suspscan
oyst-cli config set lynis.quick true
```

Scan tuning: see [pack-commands.md](pack-commands.md#scan-tuning-configtoml) and
[clamav-yara.md](clamav-yara.md).

## News

```bash
oyst-cli news list --json
oyst-cli news list --refresh --json
oyst-cli news list --sources arch,gentoo --json
oyst-cli news refresh --json
oyst-cli news refresh --sources ubuntu,debian --json
```

Selectable security advisory feeds (default: Arch / Ubuntu / Debian). Optional sources:
`arch`, `ubuntu`, `debian`, `gentoo`, `fedora`, `oss-security`. Headlines are
severity-prioritized then by date. Configure defaults with
`oyst-cli config set ui.security_news_sources arch,ubuntu,debian`.

## Updates

```bash
oyst-cli updates check --json
oyst-cli updates apply --json
```

`check` lists host package upgrades for installed packs / enabled related services.
`apply` upgrades those packages (when any), refreshes ClamAV/fangfrisch/rkhunter/maldet
definitions, then runs rkhunter propupd.

## Helper

```bash
oyst-cli install-privileged-helper
oyst-cli helper-status --json
```

Installs `oyst-helper` and fine-grained polkit actions (`io.github.asafelobotomy.helper.*` via
`pkexec` argv1). Re-run after upgrades when `helper-status` reports an outdated policy.

## Services

```bash
oyst-cli services status --json
oyst-cli services set clamd on --boot
oyst-cli services set clamonacc off
oyst-cli services set freshclam-timer on
oyst-cli services set fail2ban on --boot
oyst-cli services set maldet-monitor on
oyst-cli services set schedule-linger on
```

Logical services wrap pack/helper paths (polkit prompts unless a grant is installed).

## Auth (passwordless service lifecycle)

```bash
oyst-cli auth status --json
sudo oyst-cli auth grant-service-lifecycle [--user "$USER"]
sudo oyst-cli auth revoke-service-lifecycle
```

Grant installs `/etc/polkit-1/rules.d/49-oysterav-service-lifecycle.rules` so
`systemctl` / `maldet-config` helper actions succeed without a password for the
named user. Firewall, fail2ban mutations, and package installs still require auth.

After upgrading oysterAV, reinstall the helper so argv1-scoped polkit actions are current:

```bash
sudo oyst-cli install-privileged-helper
oyst-cli helper-status --json   # policy_current should be true
```

## Audit

```bash
oyst-cli audit list --limit 50 --json
```

## RPC server

```bash
oyst-cli serve --foreground   # --foreground kept for compatibility; always foreground
```

See [rpc-schema.md](rpc-schema.md) for JSON-RPC v2 methods and authentication.

## Shell completion

```bash
# bash
eval "$(_OYST_CLI_COMPLETE=bash_source oyst-cli)"

# zsh
eval "$(_OYST_CLI_COMPLETE=zsh_source oyst-cli)"
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Threats found (scan / pack scan findings only) |
| 2 | Error (runtime/helper/maintenance/setup failures, etc.) |
| 3 | Job busy (another scan already running) |
| 4 | Privilege / AUR / destructive-action confirmation required |
| 5 | Required pack missing |

Click usage errors (unknown options, missing required args) typically exit **1** via Click; that is separate from the threat-found code above. Prefer `--json` and documented flags for scripting.

## Runtime modes

- **Full** (default): vendored tools under `~/.local/share/oysterav/runtime/`
- **Lite**: system packages only — `oyst-cli config set runtime.mode lite`

See [packaging/lite/README.md](../../packaging/lite/README.md).

## Deferred (historical)

`job.cancel` and `job.status` are implemented (`oyst-cli job cancel` / `oyst-cli job status --json` + Scan progress). See [ADR-007](../adr/007-gui-remapping-phase.md).
