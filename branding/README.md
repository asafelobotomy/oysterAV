# oysterAV branding

## Primary app icon

- **Source:** `oysterAV-icon2.jpg` (modern shell + shield + pearl)
- **Canonical PNG:** `oysterAV-icon.png` (512×512, RGBA) — tray / install master
- **Freedesktop theme on disk:** `hicolor/{16,32,48,128,256,512}x*/apps/oysterav.png`
- **Theme icon name:** `oysterav` (matches `Icon=oysterav` in `.desktop` / autostart / metainfo)

## Alternate

- **Source:** `oysterAV-icon.jpg` (pixel-art variant)
- **Export:** `alt/oysterAV-icon-pixel.png` — marketing / future use only; not installed as `oysterav`

## Wire icons for local / `uv run` use

```bash
uv run oyst-cli desktop install
# or separately:
uv run oyst-cli desktop install-icons
uv run oyst-cli desktop install-launcher
```

This copies the hicolor tree into `~/.local/share/icons/` and installs
`~/.local/share/applications/io.github.asafelobotomy.OysterAV.desktop`
(`Icon=oysterav`, `StartupWMClass=io.github.asafelobotomy.OysterAV`).

The GUI also calls the same integration on startup (idempotent) and sets the
GTK default window icon from the theme name plus a PNG file fallback.

Manual equivalent:

```bash
cp -a branding/hicolor ~/.local/share/icons/
gtk-update-icon-cache -f ~/.local/share/icons/hicolor 2>/dev/null || true
```

Packaged installs (deb/rpm/Arch/Flatpak) ship the same theme icons system-wide.
