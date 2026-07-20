# oysterAV Flatpak

Build the GUI Flatpak (requires `flatpak-builder`):

```bash
bash scripts/build_flatpak.sh x86_64
# or:
flatpak-builder --repo=repo build-dir packaging/oysterav/flatpak/io.github.asafelobotomy.OysterAV.yml
```

The oysterav module sets `build-args: [--share=network]` so `pip3 install` can fetch hatchling and other build deps from PyPI inside the SDK.

AppStream metadata: `io.github.asafelobotomy.OysterAV.metainfo.xml` (installed into the Flatpak).

**Runtime (Full mode):** Tools install to `~/.local/share/oysterav/runtime/`. For Lite/Flatpak with host tools only, set `runtime.mode=lite` and install ClamAV on the host.

## Sandbox expectations

Flatpak is **host-tool integration**, not a confinement boundary. The manifest grants
`--filesystem=home`, `--filesystem=host`, and `org.freedesktop.Flatpak` talk so the
app can reach host scanners and `flatpak-spawn --host` for user timers and Polkit
elevation (`pkexec oyst-cli …` on the host).
Do not treat the Flatpak as a security sandbox for untrusted files.

**Privileged helper bootstrap:** Install a host package (or copy `oyst-cli` to
root-owned `/usr/bin/oyst-cli`) before using GUI Install helper / passwordless auth
from Flatpak. Elevation runs `flatpak-spawn --host pkexec /usr/bin/oyst-cli …` —
a Flatpak-only install cannot satisfy the chicken-and-egg pkexec path by itself.
Alternatively run `sudo oyst-cli install-privileged-helper` on the host terminal.

Grant access to the host ClamAV socket if needed via Flatpak permissions.

## Tray / autostart

The manifest allows talking to `org.kde.StatusNotifierWatcher` so the GTK4
StatusNotifierItem tray works. Autostart uses `flatpak run
io.github.asafelobotomy.OysterAV [--minimized]` when running inside Flatpak
(`oyst-cli desktop install-autostart`).

App icons ship from `branding/hicolor/*/apps/oysterav.png` into
`/app/share/icons/hicolor/` (theme name `oysterav`, matching `Icon=oysterav`).
See `branding/README.md` for non-Flatpak install.

## Pack tier matrix

See `oyst-cli doctor` for per-distro install hints.
