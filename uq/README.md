# oysterAV in uQ

What this folder adds to the [uQ](https://github.com/asafelobotomy/uq) desktop. Nothing reads
these files unless uQ is installed; every oysterAV package (Arch, Debian, RPM, the fpm
`.deb`/`.rpm`) installs them unconditionally.

| Folder | Installed to | What it adds |
|---|---|---|
| `widgets/oysterav/` | `/usr/share/uq/shell/widgets/oysterav/` | A **Security** tile in quick settings: ok / needs attention / threat found, and the last scan time. Click for the reasons, signature age and quarantine count. |
| `pages/oysterav-security/` | `/usr/share/uq/settings/pages/oysterav-security/` | A **Security** page in uQ Settings: status, update signatures, a rootkit check, scan a folder, the quarantine (restore, delete) and the scan schedule (on/off, how often, time). |

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
- Restoring or deleting a quarantined file, turning the schedule off and the rootkit check ask
  first (`confirm`).

## Testing

- `uv run pytest tests/test_core/test_status_summary.py tests/test_cli/test_uq_integration.py`:
  the summary, and that every declared argv parses to a real `oyst-cli` command with its
  sample arguments, that the patterns refuse option-like values, and that each package
  installs this folder.
- `uqctl integrations check uq/` checks the manifests and the QML text rule. On a machine
  without oysterAV installed it also reports that `/usr/bin/oyst-cli` does not exist.
