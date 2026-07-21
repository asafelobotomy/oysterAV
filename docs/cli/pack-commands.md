# Pack CLI Command Parity

Maps upstream tool commands to `oyst-cli` per-pack groups. Every registered pack exposes at least **`status`**. Use **`oyst-cli doctor --json`** for all packs at once.

| Pack | Tier | oyst-cli commands | Upstream equivalent | Notes |
|------|------|-------------------|---------------------|-------|
| **clamav** | required | `status`, `scan`, `backend`, `clamd start/stop/restart/status/ensure` | `clamscan`, `clamdscan`, `systemctl` | Distro-aware unit |
| **freshclam** | required | `status`, `update` | `freshclam` | Runtime mode uses bundled updater |
| **fangfrisch** | optional | `status`, `ensure-config [--force]`, `initdb`, `refresh` | `fangfrisch …` | Complements CVD; never replaces freshclam. Providers via `fangfrisch.providers`. Full mode: private pip venv via `runtime install fangfrisch` |
| **clamonacc** | recommended | `status`, `start`, `stop`, `paths list/add/remove` | `clamonacc` | Paths/excludes in config; `prevention` is preference + doctor (host co-control — [ADR-008](../adr/008-clamav-host-cocontrol.md), [operator guide](../user-guide/clamonacc-prevention.md)) |
| **rkhunter** | recommended | `status`, `scan`, `update`, `propupd --confirm`, `resolve --confirm`, `versioncheck` | `rkhunter --check/update/propupd/versioncheck` + oysterAV `/etc/rkhunter.d/` overlays | propupd/resolve require `--confirm`; `disable_tests` → `oysterav-defaults.conf` |
| **chkrootkit** | recommended | `status`, `scan` | `chkrootkit` | Full-system scan only |
| **lynis** | recommended | `status`, `audit`, `profiles list`, `container audit`, `export` | `lynis audit system`, `docker exec ... lynis` | `--scope container-host` profile |
| **maldet** | optional | `status`, `scan`, `update-sigs`, `list`, `quarantine`, `monitor *` | `maldet -a/-u/-l/-q/-m`, `systemctl maldet` | Monitor via config + systemd |
| **firewall** | recommended | `detect`, `status`, `audit`, `export`, `ufw *`, `firewalld *` | `ufw`, `firewall-cmd` | Lockout guards on enable |
| **fail2ban** | optional | `status`, `jail`, `banned`, `unban`, `jail-control enable/disable`, `reload` | `fail2ban-client` | `--confirm` on mutations |
| **unhide** | optional | `status`, `scan [--mode]` | `unhide sys/brute/quick/...` | Modes: sys, brute, quick, check, fork, proc, reverse |

## Orchestrated alternatives (better than per-pack)

| Upstream workflow | oyst-cli equivalent |
|-------------------|---------------------|
| Multi-tool home scan | `oyst-cli scan ~ --profile full` |
| Integrity / rootkit suite | `oyst-cli scan / --profile integrity` |
| Full security suite | `oyst-cli scan ~ --profile suite` | malware + rootkits path scans, then Lynis hardening audit |
| Install missing pack | `oyst-cli packs install <name>` |
| Check all packs | `oyst-cli doctor --json` |

## Safety and privilege model

Mutating commands (`firewall ufw enable`, `fail2ban unban`, `clamav clamd start`, `maldet monitor start`) run via **`oyst-helper`** with validated argv templates and polkit (`auth_admin`). Changes are logged to the security audit trail (`oyst-cli audit list`).

Compound one-auth helper flows (same shape as rkhunter `set-many`):

- **fail2ban unban** with `--ignore` / `--persist` → one `fail2ban unban-flow` privileged call
- **maldet monitor start** → one `maldet-config start-monitor` call (config write + `systemctl enable --now`)
- **rkhunter Resolve open** → Privilege Concert preflight + one `rkhunter-whitelist set-many` call

- **Firewall:** `--confirm` required for UFW enable/disable/default and UFW/firewalld rule mutations (or `--dry-run`); SSH allow rule checked before enable unless `--force-lockout-risk`
- **fail2ban:** `--confirm` required for unban, jail enable/disable, and `reload --unban`; optional `--ignore` / `--persist` for ignoreip
- **rkhunter propupd:** `--confirm` required (baseline overwrite)
- **rkhunter resolve:** `--confirm` required (writes `/etc/rkhunter.d/oysterav-whitelist.conf` only; never edits sshd or deletes files)
- **rkhunter defaults:** `rkhunter.disable_tests` writes `/etc/rkhunter.d/oysterav-defaults.conf` (DISABLE_TESTS; default `suspscan`)
- **Path removes:** `--confirm` required for `clamonacc paths remove` and `maldet monitor paths remove`
- **Lynis:** `container-host` scope uses bundled profile; per-container audit uses `docker exec`
- **maldet monitor:** requires `inotify-tools`; warns on path overlap with `clamonacc.paths`

## Scan tuning (config.toml)

Tune clamscan efficiency and detection via `oyst-cli config set` (see also [clamav-yara.md](clamav-yara.md)):

| Key | Default | Effect |
|-----|---------|--------|
| `scan.backend` | `auto` | Prefer clamd when running (much faster) |
| `scan.profile` | `quick` | Default for Scan tab / `oyst-cli scan` |
| `scan.clamav_profile` | `full` | `linux-only` adds `--scan-pe=no` on clamscan (not `runtime.mode`) |
| `schedule.backend` | `inherit` | Timer override; `inherit` follows `scan.backend` |
| `scan.max_filesize` / `max_recursion` / `max_files` | `25M` / `8` / `10000` | clamscan limits (`apply_limits_to=quick` by default) |
| `scan.exclude_dirs` | `[]` | `--exclude-dir` for clamscan (not clamonacc.exclude_paths) |
| `scan.apply_limits_to` | `quick` | `quick` or `all` profiles |
| `clamav.ignore_sigs` | `[]` | Managed `oysterav.ign2` in the ClamAV DB dir |
| `fangfrisch.providers` | `sanesecurity,urlhaus` | Rewrites fangfrisch.conf on set |
| `clamonacc.exclude_paths` | `~/.cache`, Trash | Process-mode `--exclude-list` (on-access; not scan.exclude_dirs) |
| `clamonacc.prevention` | `false` | Preference only — real blocking is host co-control ([ADR-008](../adr/008-clamav-host-cocontrol.md), [operator guide](../user-guide/clamonacc-prevention.md)) |
| `rkhunter.disable_tests` | `suspscan` | `/etc/rkhunter.d/oysterav-defaults.conf` |
| `lynis.quick` | `true` | Suite/orchestrated Lynis audits |
| `runtime.mode` | `full` | Install delivery (`full`/`lite`) — unrelated to `scan.clamav_profile` |

Recommended desktop schedule: daily `quick` profile, `schedule.backend=inherit`, `scan.backend=auto`, keep clamd running, refresh fangfrisch after freshclam via `updates apply` / maintenance.

## Intentionally not wrapped

- **maldet:** interactive report cleanup (`maldet -e`)
- **lynis:** `lynis audit dockerfile` (image build pipelines; future phase)
- **YARA:** no standalone pack — use ClamAV `.yar` drop-ins / fangfrisch; see [clamav-yara.md](clamav-yara.md)

## JSON output

`status`, `scan`, and mutating action commands accept `--json` where applicable. A few read-only helpers may be human-only; prefer `--help` if unsure.

## RPC v2 (GUI contract)

| Method | Purpose |
|--------|---------|
| `firewall.status` | Active backend probe |
| `fail2ban.unban` | Unban IP (params: `ip`, optional `jail`, `ignore`, `persist`) |
| `clamav.clamd.ensure` | Idempotent clamd start |

Full firewall DSL remains CLI-first by design (ADR-007 Wave 4 residual).
