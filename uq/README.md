# oysterAV in uQ

What this folder adds to the [uQ](https://github.com/asafelobotomy/uq) desktop. Nothing reads
these files unless uQ is installed; every oysterAV package (Arch, Debian, RPM, the fpm
`.deb`/`.rpm`) installs them unconditionally.

| Folder | Installed to | What it adds |
|---|---|---|
| `widgets/oysterav/` | `/usr/share/uq/shell/widgets/oysterav/` | A **Security** tile in quick settings: ok / needs attention / threat found, and the last scan time. Click for the reasons, signature age and quarantine count. |
| `widgets/oysterav-bar/` | `/usr/share/uq/shell/widgets/oysterav-bar/` | A **shield** in the bar (green / amber / red) from the same status as the tile. A click shows why; a notification goes out when the state gets worse. |
| `pages/oysterav-security/` | `/usr/share/uq/settings/pages/oysterav-security/` | A **Security** page in uQ Settings with seven tabs: Overview, Scans, Quarantine, Schedule, Protection, Preferences, System (below). |

## The Security page

Laid out like uQ's own Settings pages (`uq_api = 3`): tabs of cards, a bar on every read, and a plan before
anything that can't be undone.

| Tab | What it has |
|---|---|
| Overview | Protected / needs attention / threat found with the reasons, signature age, **Update signatures**, and a scan running anywhere (oysterAV, the timer, here) with its progress and a Cancel. |
| Scans | Scan a folder (quick or full) with the file count shown first, **streamed progress**, what it found with a **Quarantine** for each threat; the rootkit check; the last 20 scans. |
| Quarantine | Each file with **Restore** and **Delete**, a vault check, and a way to delete stray vault files. |
| Schedule | On or off, how often, weekday, time, what to run, quarantine or not, and **Run now**. |
| Protection | The ClamAV daemon, on-access scanning, signature updates, maldet, fail2ban and scans-while-logged-out, each a switch. |
| Preferences | Every setting `oyst-cli config show` lists, drawn from its schema and followed live from `~/.config/oysterav/config.toml`; oysterAV's own reason when it refuses a value. |
| System | Which scanners are installed (with the install command), whether the polkit helper is ready, and the audit log. |

Anything the page can't do (setup, installing scanners, firewall rules, the news feed) is behind **Open
oysterAV** in the page header.

## How it works

Both run declared `oyst-cli` commands as the user (`[[command]]` in each `.toml`); uQ spawns
them directly, never through a shell, and appends only arguments that match the declared
patterns (an absolute folder, a quarantine entry number, `hourly|daily|weekly`, `HH:MM`).

- The tile polls `oyst-cli status summary --json` once a minute. That command reads the last
  scan in history, the signature file times and the quarantine count; it never starts a scan,
  probes scanners or asks for a password.
- **Scan a folder** runs the quick (ClamAV) profile as you and quarantines nothing. Settings
  kills a command after 10 minutes, so scan large trees from oysterAV itself.
- **Check for rootkits** is the one action that needs root: `oyst-cli scan --profile integrity
  --confirm` asks once through oysterAV's own polkit helper (`oyst-helper scan-concert`), and
  uQ's polkit agent shows the prompt. Nothing on the page runs as root itself.
- Restoring, deleting or quarantining a file, deleting stray vault files, turning a service on or off,
  running the schedule now, turning it off, and the rootkit check ask first (`confirm`). Those that can't be
  undone show a **plan** under the question, from the command's own `--dry-run --json`
  (`docs/cli/reference.md`, "Plans"), so the window and the command line say the same thing.
- The page never forces anything: no declared command has `--force`, and a scan from the page never
  quarantines by itself.
- Scans stream: `oyst-cli scan --ndjson` prints `{"event":"progress",...}` lines and then
  `{"event":"result",...}`, which the page turns into a progress bar.

## Testing

- `uv run pytest tests/test_core/test_status_summary.py tests/test_cli/test_uq_integration.py tests/test_cli/test_uq_page_contract.py tests/test_cli/test_uq_fixtures.py`:
  the summary, and that every declared argv parses to a real `oyst-cli` command with its
  sample arguments, that the patterns refuse option-like values, and that each package
  installs this folder.
- `node --test 'tests/uq/*.test.mjs'` and the offscreen QML tests (`tests/uq/README.md`): `logic.js`, `page.toml`
  and every tab against a fake `ctx` that answers from fixtures recorded from the real commands.
- `uqctl integrations check uq/` checks the manifests and the QML text rule. On a machine
  without oysterAV installed it also reports that `/usr/bin/oyst-cli` does not exist.
