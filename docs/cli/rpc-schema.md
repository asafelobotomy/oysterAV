# oysterAV JSON-RPC Schema (v2)

Schema version: **2** (`SCHEMA_VERSION` in `oyst_core/serve.py`).

## Authentication

Every request must include an `auth` field with the token from `~/.local/share/oysterav/oyst.token` (mode 0600). The server verifies:

1. **SO_PEERCRED** — connecting UID must match socket owner
2. **Token** — `auth` must match the token file

CLI commands invoke `oyst_core` directly and do not require RPC auth.

## Request format

```json
{
  "method": "status.assess",
  "params": {},
  "id": 1,
  "auth": "<token>"
}
```

## Response format

Success:

```json
{
  "id": 1,
  "schema_version": 2,
  "result": { }
}
```

Error:

```json
{
  "id": 1,
  "schema_version": 2,
  "error": {
    "code": "auth_failed",
    "message": "invalid or missing RPC token"
  }
}
```

## Methods

| Method | CLI equivalent | Notes |
|--------|----------------|-------|
| `status` | `oyst-cli status --json` | Aggregate status |
| `status.assess` | `oyst-cli status assess --json` | **New in v2** |
| `pack.doctor` | `oyst-cli doctor --json` | |
| `pack.install` | `oyst-cli packs install` | |
| `setup.status` | `oyst-cli setup status --json` | |
| `setup.run` | `oyst-cli setup run` | **New in v2** |
| `job.start` | `oyst-cli scan` | |
| `job.cancel` | `oyst-cli job cancel` | Cooperative cancel between packs |
| `job.clear` | `oyst-cli job clear` | Clear stuck job lock (CLI; GUI uses cancel only) |
| `job.status` | `oyst-cli job status --json` | Live pack progress while a job is active |
| `rkhunter.scan` | `oyst-cli rkhunter scan` | |
| `rkhunter.update` | `oyst-cli rkhunter update` | |
| `rkhunter.propupd` | `oyst-cli rkhunter propupd` | |
| `rkhunter.resolve` | `oyst-cli rkhunter resolve` | whitelist overlay; `--confirm` on CLI |
| `quarantine.list` | `oyst-cli quarantine list --json` | |
| `quarantine.add` | `oyst-cli quarantine add` | |
| `quarantine.restore` | `oyst-cli quarantine restore` | |
| `quarantine.delete` | `oyst-cli quarantine delete` | |
| `quarantine.verify` | `oyst-cli quarantine verify --json` | |
| `desktop.status` | `oyst-cli desktop status --json` | Autostart / desktop integration |
| `maintenance.bootstrap` | `oyst-cli maintenance bootstrap` | |
| `maintenance.post-update` | `oyst-cli maintenance post-update` | |
| `history.list` | `oyst-cli history --json` | |
| `history.get` | `oyst-cli history show <job_id> [--json]` | Full persisted scan result |
| `history.handle_open` | `oyst-cli history handle-open` | Resolve open findings |
| `history.delete` | `oyst-cli history delete` | |
| `history.delete_all` | `oyst-cli history delete-all` | |
| `history.export` | `oyst-cli history export` | |
| `history.export_all` | `oyst-cli history export-all` | |
| `audit.list` | `oyst-cli audit list --json` | **New in v2** |
| `config.get` | `oyst-cli config get [key]` | Omit key to dump full config |
| `config.set` | `oyst-cli config set` | |
| `schedule.install` | `oyst-cli schedule install` | Compat: profile + defaults then apply stable `oyst-scan.*` units |
| `schedule.apply` | `oyst-cli schedule apply` | Materialize timer from `[schedule]` config |
| `schedule.status` | `oyst-cli schedule status --json` | Config + installed/enabled/active + next |
| `schedule.run` | `oyst-cli schedule run --json` | Timer ExecStart target |
| `schedule.linger` | `oyst-cli schedule linger --json` | |
| `schedule.enable_linger` | `oyst-cli schedule enable-linger` | |
| `runtime.status` | `oyst-cli runtime status --json` | Per-pack `installed` (private runtime) + `source` |
| `runtime.install` | `oyst-cli runtime install [pack] [--progress]` | |
| `runtime.remove` | `oyst-cli runtime remove <pack> [--progress]` | Private runtime artifacts only |
| `runtime.update` | `oyst-cli runtime update` | |
| `runtime.bootstrap` | `oyst-cli runtime bootstrap [--progress]` | **New in v2** |
| `firewall.status` | `oyst-cli firewall status --json` | Read-only backend probe |
| `fail2ban.unban` | `oyst-cli fail2ban unban` | Params: `ip`, optional `jail`, `ignore`, `persist` |
| `clamav.clamd.ensure` | `oyst-cli clamav clamd ensure` | Idempotent clamd start |
| `services.status` | `oyst-cli services status --json` | Logical service status |
| `services.set` | `oyst-cli services set` | Start/stop/enable services via helper |
| `auth.status` | `oyst-cli auth status --json` | Helper + passwordless grant status |
| `helper.install` | `oyst-cli install-privileged-helper` | Polkit-elevated install/reinstall |
| `auth.grant_service_lifecycle` | `oyst-cli auth grant-service-lifecycle` | Optional param `user` |
| `auth.revoke_service_lifecycle` | `oyst-cli auth revoke-service-lifecycle` | |
| `news.list` | `oyst-cli news list [--json] [--sources …] [--max-age-days 7\|14\|30]` | Selectable advisory feeds (severity-sorted, age-filtered) |
| `news.refresh` | `oyst-cli news refresh [--json] [--sources …]` | Force-refresh selected feeds |
| `updates.check` | `oyst-cli updates check [--json]` | Available pack/service package upgrades |
| `updates.apply` | `oyst-cli updates apply [--json]` | Upgrade packages + refresh definitions + propupd |
| `clamonacc.status` | `oyst-cli clamonacc status --json` | |
| `clamonacc.start` | `oyst-cli clamonacc start` | |
| `clamonacc.stop` | `oyst-cli clamonacc stop` | |
| `clamonacc.enable` | `oyst-cli clamonacc enable` | |
| `clamonacc.disable` | `oyst-cli clamonacc disable` | |
| `clamonacc.add_path` | `oyst-cli clamonacc paths add` | |
| `clamonacc.remove_path` | `oyst-cli clamonacc paths remove` | |
| `clamonacc.ensure_fdpass` | `oyst-cli clamonacc ensure-fdpass --confirm` | Polkit `clamd-cocontrol` |
| `clamonacc.ensure_prevention` | `oyst-cli clamonacc ensure-prevention --confirm` | Polkit `clamd-cocontrol` |
| `virusevent.status` | `oyst-cli virusevent status --json` | |
| `virusevent.ensure` | `oyst-cli virusevent ensure --confirm` | Polkit `clamd-cocontrol` |
| `clamav.ensure_disable_cache` | `oyst-cli clamav ensure-disable-cache --confirm` | Polkit `clamd-cocontrol` |

## Changelog v1 → v2

- Added RPC authentication (peer UID + token)
- Structured error objects (`code`, `message`) instead of raw exception strings
- Added `status.assess`, `setup.run`, `runtime.bootstrap`, `audit.list`
- Added `runtime.remove` (private runtime uninstall) and CLI `--progress` NDJSON for install/remove/bootstrap
- Added `firewall.status`, `fail2ban.unban`, `clamav.clamd.ensure` (mutating firewall DSL remains CLI-only)
- Added `services.status` / `services.set` and `auth.status`
- Added `helper.install`, `auth.grant_service_lifecycle`, `auth.revoke_service_lifecycle` (Polkit via backend; GUI Install button + passwordless toggle)
- `schedule.install` validates profile against `ScanProfile` enum; units are `oyst-scan.service` / `oyst-scan.timer` with `ExecStart=… schedule run`
- Added `schedule.apply` and `schedule.run`
- Added `clamonacc.*` and `news.list` / `news.refresh`
- Long-running methods use extended client timeouts and newline-framed responses

## Serve lifecycle

```bash
oyst-cli serve --foreground
```

Systemd user unit template:

```ini
[Unit]
Description=oysterAV RPC backend

[Service]
ExecStart=%h/.local/bin/oyst-cli serve --foreground
Restart=on-failure

[Install]
WantedBy=default.target
```
