# oysterAV Flatpak

Build the GUI Flatpak (requires `flatpak-builder`):

```bash
flatpak-builder --repo=repo build-dir packaging/oysterav/flatpak/io.github.oysterav.OysterAV.yml
```

**Runtime (Full mode):** Tools install to `~/.local/share/oysterav/runtime/`. For Lite/Flatpak with host tools only, set `runtime.mode=lite` and install ClamAV on the host.

## Sandbox expectations

Flatpak is **host-tool integration**, not a confinement boundary. The manifest grants
`--filesystem=home`, `--filesystem=host`, and `org.freedesktop.Flatpak` talk so the
app can reach host scanners and `flatpak-spawn --host systemctl` for user timers.
Do not treat the Flatpak as a security sandbox for untrusted files.

Grant access to the host ClamAV socket if needed via Flatpak permissions.

## Tray / autostart

The manifest allows talking to `org.kde.StatusNotifierWatcher` so the GTK4
StatusNotifierItem tray works. Autostart uses `flatpak run
io.github.oysterav.OysterAV [--minimized]` when running inside Flatpak
(`oyst-cli desktop install-autostart`).

App icons ship from `branding/hicolor/*/apps/oysterav.png` into
`/app/share/icons/hicolor/` (theme name `oysterav`, matching `Icon=oysterav`).
See `branding/README.md` for non-Flatpak install.

## Pack tier matrix

See `oyst-cli doctor` for per-distro install hints.
