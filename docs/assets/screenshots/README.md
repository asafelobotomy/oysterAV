# GUI screenshots

Marketing / README captures of the oysterAV GTK4 UI (default 960×700 window).

| File | Tab |
|------|-----|
| `dashboard.png` | Dashboard — posture cards, ticker, recent scans |
| `scan.png` | Scan — profiles, paths, pack cards |
| `shield.png` | Shield — firewall, fail2ban |
| `reports.png` | Reports — history / export |
| `quarantine.png` | Quarantine — vault |
| `settings.png` | Settings — categories sidebar |

Regenerate on a desktop session (no portal / IDE chrome):

```bash
uv sync --extra gui
uv run python scripts/capture_gui_screenshots.py
```

Do not commit full-desktop captures that include unrelated IDE chrome.
