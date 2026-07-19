# oysterAV branding

## Primary app icon

- **Source:** `oysterAV-icon2.jpg` (modern shell + shield + pearl)
- **Canonical PNG:** `oysterAV-icon.png` (512×512, RGBA) — used by the tray and as the install master name
- **Freedesktop theme on disk:** `hicolor/{16,32,48,128,256}x*/apps/oysterav.png`
- **512 theme icon:** installed from `oysterAV-icon.png` at pack time (Flatpak) or via optional local copy into `hicolor/512x512/apps/oysterav.png`
- **Theme icon name:** `oysterav` (matches `Icon=oysterav` in `.desktop` / autostart)

## Alternate

- **Source:** `oysterAV-icon.jpg` (pixel-art variant)
- **Export:** `alt/oysterAV-icon-pixel.png` — marketing / future use only; not installed as `oysterav`

## Non-Flatpak install

Copy the theme tree so launchers and the window icon resolve:

```bash
cp -a branding/hicolor ~/.local/share/icons/
install -Dm644 branding/oysterAV-icon.png \
  ~/.local/share/icons/hicolor/512x512/apps/oysterav.png
gtk-update-icon-cache -f ~/.local/share/icons/hicolor 2>/dev/null || true
```

From a source checkout, the GUI also adds `branding/` to the GTK icon-theme search path and falls back to `oysterAV-icon.png` for the tray.
