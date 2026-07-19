"""XDG desktop / autostart helpers for oysterAV GUI."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

APP_ID = "io.github.oysterav.OysterAV"
AUTOSTART_FILENAME = f"{APP_ID}.desktop"


def is_flatpak() -> bool:
    return Path("/.flatpak-info").exists()


def autostart_dir() -> Path:
    path = Path.home() / ".config" / "autostart"
    path.mkdir(parents=True, exist_ok=True)
    return path


def autostart_path() -> Path:
    return autostart_dir() / AUTOSTART_FILENAME


def resolve_oysterav_exec() -> str:
    """Resolve command used in .desktop Exec= lines."""
    if is_flatpak():
        return f"flatpak run {APP_ID}"
    found = shutil.which("oysterav")
    if found:
        return found
    # Prefer the interpreter's sibling if installed in a venv
    sibling = Path(sys.executable).resolve().parent / "oysterav"
    if sibling.is_file():
        return str(sibling)
    return "oysterav"


def probe_tray_library() -> dict[str, object]:
    """Report whether a tray host / bindings are available."""
    ayatana: dict[str, object] = {"available": False, "library": "", "version": ""}
    for name, version in (
        ("AyatanaAppIndicator3", "0.1"),
        ("AppIndicator3", "0.1"),
    ):
        try:
            import gi

            gi.require_version(name, version)
            __import__(f"gi.repository.{name}")
            ayatana = {"available": True, "library": name, "version": version}
            break
        except (ValueError, ImportError, AttributeError):
            continue

    watcher = False
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio

        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        bus.call_sync(
            "org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            "org.freedesktop.DBus.Peer",
            "Ping",
            None,
            None,
            Gio.DBusCallFlags.NONE,
            1000,
            None,
        )
        watcher = True
    except Exception:  # noqa: BLE001 — probe only
        watcher = False

    available = bool(ayatana.get("available")) or watcher
    hint = ""
    if not available:
        hint = (
            "No StatusNotifierWatcher / AppIndicator present. "
            "Install a tray host (e.g. ayatana indicators) for minimize-to-tray."
        )
    return {
        "available": available,
        "status_notifier_watcher": watcher,
        "ayatana": ayatana,
        "library": ayatana.get("library") or ("StatusNotifierItem" if watcher else ""),
        "version": ayatana.get("version") or "",
        "hint": hint,
    }


def build_desktop_entry(*, minimized: bool = False, for_autostart: bool = True) -> str:
    exec_cmd = resolve_oysterav_exec()
    if minimized:
        exec_cmd = f"{exec_cmd} --minimized"
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.0",
        "Name=oysterAV",
        "Comment=Linux security orchestrator",
        f"Exec={exec_cmd}",
        "Icon=oysterav",
        "Terminal=false",
        "Categories=System;Security;",
        "X-GNOME-Autostart-enabled=true",
        f"StartupWMClass={APP_ID}",
    ]
    if for_autostart:
        lines.append("X-GNOME-Autostart-Phase=Application")
    return "\n".join(lines) + "\n"


def install_autostart(*, minimized: bool | None = None) -> dict[str, object]:
    from oyst_core.config import load_config, save_config

    cfg = load_config()
    if minimized is None:
        minimized = cfg.ui.start_minimized
    path = autostart_path()
    entry = build_desktop_entry(minimized=bool(minimized), for_autostart=True)
    path.write_text(entry, encoding="utf-8")
    cfg.ui.run_at_startup = True
    save_config(cfg)
    return {
        "ok": True,
        "path": str(path),
        "minimized": bool(minimized),
        "exec": resolve_oysterav_exec() + (" --minimized" if minimized else ""),
        "message": f"Autostart installed at {path}",
    }


def remove_autostart() -> dict[str, object]:
    from oyst_core.config import load_config, save_config

    path = autostart_path()
    existed = path.is_file()
    path.unlink(missing_ok=True)
    cfg = load_config()
    cfg.ui.run_at_startup = False
    save_config(cfg)
    return {
        "ok": True,
        "path": str(path),
        "removed": existed,
        "message": "Autostart removed" if existed else "Autostart was not present",
    }


def sync_autostart_from_config() -> dict[str, object]:
    """Install or remove autostart to match ui.run_at_startup / ui.start_minimized."""
    from oyst_core.config import load_config

    cfg = load_config()
    if cfg.ui.run_at_startup:
        return install_autostart(minimized=cfg.ui.start_minimized)
    return remove_autostart()


def rewrite_autostart_if_enabled() -> dict[str, object] | None:
    """Rewrite Exec line when start_minimized changes and autostart is on."""
    from oyst_core.config import load_config

    cfg = load_config()
    if not cfg.ui.run_at_startup:
        return None
    return install_autostart(minimized=cfg.ui.start_minimized)


def autostart_status() -> dict[str, object]:
    from oyst_core.config import load_config

    cfg = load_config()
    path = autostart_path()
    present = path.is_file()
    tray = probe_tray_library()
    return {
        "run_at_startup": cfg.ui.run_at_startup,
        "start_minimized": cfg.ui.start_minimized,
        "minimize_to_tray": cfg.ui.minimize_to_tray,
        "autostart_path": str(path),
        "autostart_present": present,
        "flatpak": is_flatpak(),
        "exec": resolve_oysterav_exec(),
        "tray": tray,
    }
