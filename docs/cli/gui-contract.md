# GUI → CLI Contract

Living document mapping every GTK user-facing feature to CLI-first equivalents
([ADR-007](../adr/007-gui-remapping-phase.md) remapping phase; [ADR-002](../adr/002-cli-first-gui-is-client.md): CLI remains source of truth).

## Parity rules

1. **Every RPC method the GUI calls** must have a CLI command (`tests/test_cli/test_rpc_parity.py`).
2. **Every GUI workflow** must be reproducible with documented `oyst-cli` commands (this file).
3. **CLI may exceed GUI** — pack subcommands, `status assess`, `setup run`, audit trail, etc. are CLI-first extras.
4. **GUI may compose multiple RPC calls** — CLI often provides a single orchestrated command that is simpler.

### Coverage vs parity

| Layer | Role |
|-------|------|
| Parity AST / `--help` | Contract: method exists and maps to CLI (not behavioral coverage) |
| [`oysterav/gui/rpc_actions.py`](../../oysterav/gui/rpc_actions.py) + `tests/test_core/test_rpc_actions.py` | ADR-007 wiring: cancel, services, quarantine add, host security, audit, news |
| Core/CLI unit tests | Mutations, parsers, allowlists (mocked tools) |
| `fail_under` in `pyproject.toml` | Floor on `oyst_core` + `oyst_cli` line coverage only (`oysterav` excluded) |

## Application shell

| GUI feature | CLI equivalent |
|-------------|----------------|
| Auto-start RPC backend on launch | `oyst-cli serve` / `oyst-cli serve --foreground` (flag kept for compatibility; always foreground; or systemd user unit in docs) |
| Tab switcher (Dashboard / Scan / Quarantine / Settings) | No single command — use tab-specific commands below |
| Global status bar (operational messages) | stderr/stdout from CLI commands |
| Update alert (idle; yellow; above news) | **`oyst-cli updates check --json`** (`updates.check`) |
| Security news ticker (idle status bar; below updates) | **`oyst-cli news list [--json] [--sources …]`** / `oyst-cli news refresh` |
| Auto setup wizard on first launch | `oyst-cli setup check` (exit 1 = show wizard equivalent) |

---

## Dashboard tab

Posture-only: health cards, banner, and recent scans. Runtime bootstrap and pack doctor live under **Settings → Maintenance / Security packs**.

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Health banner (missing packs, stale sigs, clamd down, active job) | `status.assess` | **`oyst-cli status assess --json`** (severity, recommended actions) |
| Banner → Open Settings | — | `oyst-cli doctor --json` then `oyst-cli packs install <name>` |
| ClamAV status card | `status`; tap when stopped → `clamav.clamd.ensure` | `oyst-cli status --json`; **`oyst-cli clamav clamd ensure`** |
| Signatures status card | `status` | `oyst-cli status --json` (field: `signature_age_hours`) |
| Last Scan card | `status` | `oyst-cli status --json` + `oyst-cli history --json` |
| Quarantine count card | `quarantine.list` | `oyst-cli quarantine list --json` |
| Recent scans list | `history.list` | `oyst-cli history --json` |
| Recent scans → open report | navigate Reports + `history.get` | `oyst-cli history show <job_id> --json` |
| Refresh on tab visit | `status`, `history.list`, `quarantine.list` | Same three commands |

**Dashboard one-liner (scripting):**

```bash
oyst-cli status assess --json
oyst-cli history --json
oyst-cli quarantine list --json
```

---

## Scan tab

Two-column layout (stacks vertically on narrow windows): **Scan** controls (left) and **Scan Progress** + **Scan Results** pack cards (right). In-flight scans can be cancelled via `job.cancel`; live pack progress via `job.status`.

### Scan controls

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| **Run scan** | `job.start` (quarantine follows Settings `quarantine.auto`) | `oyst-cli scan [paths] --profile <p> [--quarantine] [--json]` |
| Browse folder / Browse file / Clear path | — | Path arguments to `oyst-cli scan` |
| Selected path label | — | — |
| Profile: Quick / Full / Suite / Integrity / Custom | — (passed to scan) | `oyst-cli scan --profile quick\|full\|suite\|integrity\|custom` |
| Custom pack checkboxes (clamav, maldet, rkhunter, chkrootkit, unhide, lynis) | `job.start` `packs` | `oyst-cli scan --profile custom --packs clamav,rkhunter,lynis …` |
| Cancel in-flight scan | `job.cancel` | `oyst-cli job cancel` |
| Target: Home / Downloads / Desktop / Custom (hidden for Integrity) | — | `oyst-cli scan ~/Downloads` or explicit paths |

Integrity runs system-wide packs (`rkhunter`, `chkrootkit`, `unhide`); path controls are hidden. Custom profile exposes a pack picker on this tab.

### Scan Progress / Results

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Live pack progress (poll while scanning) | `job.status` | `oyst-cli job status --json` |
| Per-pack result cards (clamav, maldet, rkhunter, chkrootkit, unhide, lynis) | — (from `job.start` result) | `--json` on scan output |
| Pack detail dialog (grouped findings + quarantine/propupd/resolve/copy) | `quarantine.add` / `rkhunter.propupd` / `rkhunter.resolve` when applicable | `oyst-cli quarantine add`; `oyst-cli rkhunter propupd --confirm`; `oyst-cli rkhunter resolve --confirm` |

Rootkit packs run through orchestrated profiles (Integrity / Suite / Custom), not a separate Scan-tab button. CLI `oyst-cli rkhunter scan` remains available.

rkhunter `--update` / `--propupd` live under **Settings → Maintenance** (not on Scan). Auto-quarantine for malware scans is **Settings → General**.

---

## Reports tab

Master–detail scan history (list + summary + findings). Findings are grouped by pack, message-first, with a render cap and safe actions when a real path or maintenance command applies.

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Scan list | `history.list` | `oyst-cli history --json` |
| Selected scan detail | `history.get` | `oyst-cli history show <job_id> --json` |
| **Refresh** | `history.list` | `oyst-cli history --json` |
| Refresh on tab visit | `history.list` | `oyst-cli history --json` |
| Finding summary (pack / severity counts; open vs handled badge) | — (from `history.get` findings) | — |
| **Export** / **Export all** (JSON or Markdown; save dialog) | `history.export` / `history.export_all` | `oyst-cli history export <job_id> -o FILE --format json\|md`; `oyst-cli history export-all -o FILE --format json\|md` |
| **Delete** / **Delete all** (confirm) | `history.delete` / `history.delete_all` | `oyst-cli history delete <job_id> --confirm`; `oyst-cli history delete-all --confirm` |
| **Quarantine** (confirm; clamav/maldet + existing file path; patches history when `job_id` set) | `quarantine.add` | `oyst-cli quarantine add <path> [--job-id …]` |
| Disabled **Quarantined** label (after auto/manual quarantine or vault path match) | — (finding `quarantined` flag / vault heuristic) | — |
| **Refresh rkhunter baseline** (confirm; propupd advisories) | `rkhunter.propupd` | `oyst-cli rkhunter propupd --confirm [--json]` |
| **Resolve** (confirm; whitelist script/hidden/SSH advisories; patches history when `job_id` set) | `rkhunter.resolve` | `oyst-cli rkhunter resolve --threat … [--path …] [--message …] [--job-id …] --confirm [--json]` |
| Disabled **Resolved** label (after resolve or overlay match) | — (finding `resolved` flag / overlay heuristic) | — |
| **Quarantine open** / **Resolve open** (one confirm; per-item gates; partial failures reported) | `history.handle_open` | `oyst-cli history handle-open <job_id> --quarantine\|--resolve --confirm [--json]` |
| Resolve open auth | one `rkhunter-whitelist set-many` polkit prompt for the whole batch | same CLI path |
| Copy path / message | — (clipboard) | — |
| Review manually hint (chkrootkit / unhide / lynis / non-actionable rkhunter) | — | — |

Scan pack result dialog reuses the same finding presentation and actions.

---

## Quarantine tab

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Entry list | `quarantine.list` | `oyst-cli quarantine list --json` |
| Entry detail | — (from list) | `oyst-cli quarantine show <id> --json` |
| **Refresh** | `quarantine.list` | `oyst-cli quarantine list --json` |
| **Restore** | `quarantine.restore` | `oyst-cli quarantine restore <id> --confirm [--json]` |
| **Delete** | `quarantine.delete` | `oyst-cli quarantine delete <id> --confirm [--json]` |
| **Verify vault** | `quarantine.verify` | `oyst-cli quarantine verify --json` |
| **Add file** (file chooser) | `quarantine.add` | `oyst-cli quarantine add <path>` |

Quarantine from Reports / Scan finding rows also uses `quarantine.add` when the finding has a real malware-pack file path.

---

## Settings tab

Sidebar navigation (wizard-style ListBox + stack). Section order:

**General → Services → Real-time → Scheduling → Host & audit → Maintenance → Security packs.**

Dashboard “Open Settings” (missing required packs) deep-links to **Security packs**; other entry points default to **General**.

### General preferences

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| oyst-cli backend connection status | `config.get` (probe on Settings refresh) | `oyst-cli status --json` / serve health |
| Security news ticker | `config.set ui.security_news` + `news.list` | `oyst-cli config set ui.security_news true\|false`; `oyst-cli news list` |
| News sources (multi-select) | `config.set ui.security_news_sources` + force `news.refresh` | `oyst-cli config set ui.security_news_sources arch,ubuntu,debian[,gentoo,fedora,oss-security]`; `news list --sources …` |
| Refresh security news | `news.refresh` | `oyst-cli news refresh [--json] [--sources …]` |
| Auto-quarantine threats | `config.set quarantine.auto` | `oyst-cli config set quarantine.auto true` |
| Scan backend | `config.set scan.backend` | `oyst-cli config set scan.backend auto\|clamd\|clamscan` |
| Default scan profile | `config.set scan.profile` | `oyst-cli config set scan.profile quick\|…` (Scan tab + CLI default) |
| Clamonacc enable | Real-time switch → `clamonacc.enable/disable` | Services shows status only (no duplicate toggle) |
| Theme | `config.set ui.theme` | `oyst-cli config set ui.theme gruvbox-dark-hard\|…\|system` (default: Gruvbox Dark Hard) |
| Run at startup | `config.set ui.run_at_startup` | `oyst-cli desktop install-autostart` / `remove-autostart` or `config set ui.run_at_startup` |
| Start minimized | `config.set ui.start_minimized` | `oyst-cli config set ui.start_minimized true` (+ `oysterav --minimized`) |
| Minimize to tray on close | `config.set ui.minimize_to_tray` | `oyst-cli config set ui.minimize_to_tray true` |

Probe tray + autostart: `oyst-cli desktop status --json`. Theme and desktop launch prefs live under **Appearance & desktop** in the General section (scan defaults are a separate group).

### Services

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Privileged helper Install/Reinstall/Update | `helper.install` | `oyst-cli install-privileged-helper` (via Polkit) |
| Passwordless service control | `auth.grant_service_lifecycle` / `auth.revoke_service_lifecycle` | `oyst-cli auth grant/revoke-service-lifecycle` |
| Per-service on/off (clamd, freshclam-timer, fail2ban, maldet-monitor, schedule-linger) | `services.set` | `oyst-cli services set <name> on\|off` |
| Clamonacc unit status (read-only) | `services.status` | Status only — enable/disable under **Real-time** |

Clamonacc under Services is **status-only** (no `services.set` toggle). Paths and on-access enable live under **Real-time** (`clamonacc.*`). See also [Settings Services / Auth](#settings-services--auth-adr-007-wave-2).

### Real-time monitoring

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Clamonacc enabled switch | `clamonacc.enable` / `clamonacc.disable` | `oyst-cli clamonacc enable` / `disable` |
| Watched paths | `clamonacc.add_path` / `clamonacc.remove_path` | **`oyst-cli clamonacc paths add/remove <path>`** |

### Scheduling

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Timer status subtitle | `schedule.status` | `oyst-cli schedule status --json` (merged config + systemd + next + linger) |
| Schedule prefs (enabled, profile, frequency, time, weekday, OnCalendar, packs, paths, quarantine, backend, persistent) | `config.set schedule.*` then auto `schedule.apply` | `oyst-cli schedule set …` / `config set schedule.*` then `schedule apply` |
| Schedule backend (timer override) | `config.set schedule.backend` | `inherit` follows General scan backend; or `auto\|clamd\|clamscan` |
| Schedule time (HH:MM) | `config.set schedule.time` | Validated as 24-hour `HH:MM` in GUI and `config set` |
| **Run now** | `schedule.run` | `oyst-cli schedule run [--json]` |
| Pre-apply validation (Custom OnCalendar / Custom packs / HH:MM) | — (GUI) | Same rules as `schedule.apply` validation |
| Linger advisory dialog (once per session when needed) | `schedule.linger` + `schedule.enable_linger` | `oyst-cli schedule linger --json` then `oyst-cli schedule enable-linger` |
| Timer failure hint dialog | — | stderr from `schedule apply`; see `schedule status --json` |

Schedule quarantine/backend are **timer overrides** of General defaults.

### Host & audit

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Firewall status | `firewall.status` | `oyst-cli firewall status` (full DSL remains CLI) |
| fail2ban unban IP | `fail2ban.unban` | `oyst-cli fail2ban unban <ip> --confirm` |
| Audit trail (recent entries) | `audit.list` | `oyst-cli audit list` (display-only in GUI) |

### Maintenance

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| **Update all** | `updates.apply` | **`oyst-cli updates apply [--json]`** (check → package upgrades → signatures/definitions → rkhunter propupd) |
| **Install runtime and update signatures** | `runtime.bootstrap` | **`oyst-cli runtime bootstrap`** |
| **Maintenance only** | `maintenance.bootstrap` | `oyst-cli maintenance bootstrap` |
| **Post-update maintenance** | `maintenance.post_update` | `oyst-cli maintenance post-update` |
| **Update rkhunter data** | `rkhunter.update` | `oyst-cli rkhunter update [--json]` |
| **Refresh rkhunter baseline** (confirm dialog) | `rkhunter.propupd` | `oyst-cli rkhunter propupd --confirm [--json]` |
| Last run status | — (GUI label) | Inspect bootstrap/maintenance CLI output |
| **Run setup wizard** | Opens SetupWizard | Step through wizard, or use Auto-Install |

Maintenance only may include rkhunter propupd as part of the bundle without the discrete-confirm modal. Update rkhunter data refreshes rkhunter files only (not ClamAV signatures).

### Security packs

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| Pack list by tier | `pack.doctor` | `oyst-cli doctor --json` or `oyst-cli packs list --json` |
| Origin (Private/System) + description + path + version | `pack.doctor` + `runtime.status` | `oyst-cli doctor --json`; `oyst-cli runtime status --json` |
| **Install** / **Install to runtime** | `pack.install` / `runtime.install` | `oyst-cli packs install <name>` / `runtime install <name>` |
| **Remove** (private only) | `runtime.remove` | `oyst-cli runtime remove <name> --confirm [--progress]` |
| AUR confirm dialog | `pack.install(confirm_aur=true)` | `--confirm-aur` flag |

System PATH and private runtime both count as installed. Remove deletes only a private copy.

Settings Scheduling is the GUI editor for `[schedule]`; Apply materializes `oyst-scan.timer`.

### Setup

| GUI feature | RPC / client | CLI equivalent |
|-------------|--------------|----------------|
| **Run setup wizard** (under Maintenance) | Opens SetupWizard | Step through wizard, or use Auto-Install |
| **Auto-Install** (wizard welcome) | `setup.run` | **`oyst-cli setup run --enable-linger`** |

---

## Setup wizard (5 pages)

Pages: Welcome → Security packs → Preferences → Scheduling → Ready.

| Wizard page / action | GUI RPC composition | CLI equivalent |
|----------------------|---------------------|----------------|
| Auto-show gate | `setup.status` + `status` | `oyst-cli setup check --json` |
| Auto-Install (welcome) | `setup.run` (`enable_linger`) | **`oyst-cli setup run --enable-linger`** |
| Security packs — status / refresh | `pack.doctor` + `setup.status` + `runtime.status` | `oyst-cli doctor --json`; `setup check`; `runtime status` |
| Security packs — per-pack install | `pack.install` / `runtime.install` | `oyst-cli packs install` / `runtime install` |
| Security packs — Continue anyway | `config.set setup.skipped_steps` | Honored by `setup.status` / `setup check` once setup is marked complete |
| Security packs — Install runtime and update signatures | `runtime.bootstrap` | **`oyst-cli runtime bootstrap`** or `setup run` |
| Security packs — Maintenance only | `maintenance.bootstrap` | `oyst-cli maintenance bootstrap` |
| Preferences (auto-quarantine) | `config.set quarantine.auto` on finish | `setup run --auto-quarantine` or `config set quarantine.auto` |
| Install scheduled scan timer (profile / frequency / time) | `schedule.apply` | `setup run` or `schedule apply` |
| Linger prompt | `schedule.enable_linger` (Auto-Install via `setup.run`; manual Install may prompt) | `setup run --enable-linger` / `schedule enable-linger` |
| Finish / mark complete | `config.set setup.completed` via `setup.run` | Automatic on successful `setup run` |
| Ready summary checklist | — (GUI) | — |
| Cancel | — (no mark complete) | Do not run `setup run`; or `setup run --no-mark-complete` |

**Auto-Install defaults:** quick profile, daily at 02:00, linger enabled, full runtime bootstrap. Step-through Scheduling widgets apply only when you install the timer manually on that page.

**Preferred first-run path:**

```bash
oyst-cli setup check --json
oyst-cli setup run --confirm-aur --enable-linger --json
oyst-cli status assess --json
```

---

## RPC methods used by GUI → CLI

RPC methods invoked from GTK widgets (via `OystClient`) have CLI commands. Dashboard already uses `status.assess`. Scan cancel uses `job.cancel`.

| RPC method | CLI |
|------------|-----|
| `status` | `oyst-cli status --json` |
| `status.assess` | `oyst-cli status assess --json` (Dashboard health banner) |
| `history.list` | `oyst-cli history --json` |
| `history.get` | `oyst-cli history show <job_id> --json` |
| `quarantine.list` | `oyst-cli quarantine list --json` |
| `quarantine.restore` | `oyst-cli quarantine restore <id> --confirm` |
| `quarantine.delete` | `oyst-cli quarantine delete <id> --confirm` |
| `quarantine.verify` | `oyst-cli quarantine verify --json` |
| `pack.doctor` | `oyst-cli doctor --json` |
| `pack.install` | `oyst-cli packs install <name>` |
| `job.start` | `oyst-cli scan [paths] [--profile] [--quarantine]` |
| `job.cancel` | `oyst-cli job cancel` |
| `job.status` | `oyst-cli job status --json` |
| `rkhunter.update` | `oyst-cli rkhunter update` |
| `rkhunter.propupd` | `oyst-cli rkhunter propupd --confirm` |
| `rkhunter.resolve` | `oyst-cli rkhunter resolve --threat … --confirm` |
| `config.get` | `oyst-cli config get [key] [--json]` |
| `config.set` | `oyst-cli config set <key> <value>` |
| `setup.status` | `oyst-cli setup status --json` |
| `setup.run` | `oyst-cli setup run` (GUI Auto-Install on wizard welcome) |
| `schedule.install` | `oyst-cli schedule install` |
| `schedule.apply` | `oyst-cli schedule apply` |
| `schedule.status` | `oyst-cli schedule status --json` |
| `schedule.run` | `oyst-cli schedule run --json` |
| `schedule.linger` | `oyst-cli schedule linger --json` |
| `schedule.enable_linger` | `oyst-cli schedule enable-linger` |
| `runtime.status` | `oyst-cli runtime status --json` |
| `runtime.install` | `oyst-cli runtime install` |
| `runtime.remove` | `oyst-cli runtime remove <name> --confirm` |
| `runtime.update` | `oyst-cli runtime update` |
| `runtime.bootstrap` | `oyst-cli runtime bootstrap` |
| `maintenance.bootstrap` | `oyst-cli maintenance bootstrap` |
| `maintenance.post-update` | `oyst-cli maintenance post-update` | Settings → Maintenance |
| `updates.check` | `oyst-cli updates check [--json]` | Status bar alerts |
| `updates.apply` | `oyst-cli updates apply [--json]` | Settings → Maintenance → Update all |
| `clamav.clamd.ensure` | `oyst-cli clamav clamd ensure` |
| `services.status` | `oyst-cli services status --json` |
| `services.set` | `oyst-cli services set <name> on\|off [--boot]` |
| `auth.status` | `oyst-cli auth status --json` |
| `quarantine.add` | `oyst-cli quarantine add` |
| `desktop.status` | `oyst-cli desktop status --json` |
| `clamonacc.*` | `oyst-cli clamonacc …` |
| `news.list` | `oyst-cli news list [--json] [--sources …]` |
| `news.refresh` | `oyst-cli news refresh [--json] [--sources …]` |

Enforced by `tests/test_cli/test_gui_cli_parity.py` and `tests/test_cli/test_rpc_parity.py`.

---

## Settings Services / Auth (ADR-007 Wave 2)

| GUI feature | RPC / CLI |
|-------------|-----------|
| Per-service on/off (+ boot) | `services.set` / `oyst-cli services set` |
| Service status refresh | `services.status` |
| Helper status | `auth.status` / `helper-status` |
| Helper install / reinstall | `helper.install` → Polkit (`pkexec oyst-cli install-privileged-helper`) |
| Passwordless grant/revoke toggle | `auth.grant_service_lifecycle` / `auth.revoke_service_lifecycle` → Polkit |

Elevation stays in `oyst_core` (not the GTK process). ADR-002 forbids `pkexec` in
`oysterav/`; CI greps for GUI security subprocesses.

---

## CLI-first / advanced (intentional — not full GUI)

These stay CLI-first by design (ADR-007 Wave 4 residual). GUI may show status or a
narrow action only; full DSL remains `oyst-cli`.

| Capability | CLI | GUI surface |
|------------|-----|-------------|
| Setup gate / reset | `setup check`, `setup reset` | None (wizard uses `setup.run` / `setup.status`) |
| Firewall rule DSL | `firewall ufw|firewalld …` | Host security: **status only** (`firewall.status`) |
| fail2ban unban (+ optional ignore/persist; one auth) | `fail2ban unban … --confirm [--ignore] [--persist]` | Host security: **unban IP** (`fail2ban.unban`) |
| fail2ban jail control / reload | `fail2ban jail-control`, `reload`, … | CLI-first remainder |
| maldet monitor start (config + enable; one auth) | `maldet monitor start` | Services / pack monitor controls |
| Deep pack ops | `fangfrisch`, `lynis audit`, `maldet scan`, `chkrootkit`, `unhide`, `freshclam update` | Packs list install/remove; Scan profiles; not full pack CLIs |
| Privileged helper / auth grant | `install-privileged-helper`, `auth grant/revoke-service-lifecycle` | Services: Install button + passwordless switch (`helper.install` / `auth.grant*` / `auth.revoke*`) |

Parity discovery: `test_gui_cli_parity` walks AST for both `client.foo()` calls and
bound-method references (`run_in_thread(self.client.foo, …)`).

See [pack-commands.md](pack-commands.md) for the full pack inventory.

---

## Known GUI ↔ CLI behavioral differences

| Topic | GUI | CLI |
|-------|-----|-----|
| Setup | 5-page wizard with granular RPC calls | Single `setup run` batch workflow |
| Failure UX | Copy-to-clipboard command dialogs | Commands are run directly; use `--json` for scripting |
| AUR installs | Per-pack modal confirm | `--confirm-aur` on install/setup |
| fail2ban unban | MessageDialog before RPC | `--confirm` required |
| Update all | MessageDialog (notes rkhunter propupd) | `updates apply --confirm` |
| Quarantine add | File picker (findings use dialog) | `quarantine add --confirm` |
| RPC confirms | UX dialogs in GUI; not an RPC auth flag | `--confirm` is CLI footgun prevention only |
| data paths | Uses `~/.local/share/oysterav` (hardcoded; ignores `XDG_DATA_HOME`) | Same |

---

## Audit parity

Sensitive mutations log to the security audit trail from core functions (`set_config_value`, quarantine restore/delete, schedule install/enable-linger) so CLI and RPC paths behave identically. Query with `oyst-cli audit list --json`.
