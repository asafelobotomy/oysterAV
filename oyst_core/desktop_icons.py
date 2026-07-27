"""Install oysterAV icons and applications launcher into user XDG dirs."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from oyst_core.desktop_util import APP_ID, build_desktop_entry, is_flatpak

ICON_NAME = "oysterav"
ICON_SIZES = (16, 32, 48, 128, 256, 512)


def branding_dir() -> Path:
    """Repo ``branding/`` next to the ``oyst_core`` package (source checkout)."""
    return Path(__file__).resolve().parents[1] / "branding"


def user_icons_root() -> Path:
    return Path.home() / ".local" / "share" / "icons" / "hicolor"


def user_applications_dir() -> Path:
    path = Path.home() / ".local" / "share" / "applications"
    path.mkdir(parents=True, exist_ok=True)
    return path


def user_launcher_path() -> Path:
    return user_applications_dir() / f"{APP_ID}.desktop"


def resolve_icon_png(*, size: int | None = None) -> Path | None:
    """Best on-disk PNG for theme name ``oysterav`` (checkout or user install)."""
    branding = branding_dir()
    candidates: list[Path] = []
    if size is not None:
        candidates.append(branding / "hicolor" / f"{size}x{size}" / "apps" / f"{ICON_NAME}.png")
    candidates.extend(
        [
            branding / "hicolor" / "512x512" / "apps" / f"{ICON_NAME}.png",
            branding / "oysterAV-icon.png",
            branding / "hicolor" / "256x256" / "apps" / f"{ICON_NAME}.png",
            Path("/app/share/icons/hicolor/256x256/apps") / f"{ICON_NAME}.png",
            user_icons_root() / "256x256" / "apps" / f"{ICON_NAME}.png",
            Path("/usr/share/icons/hicolor/256x256/apps") / f"{ICON_NAME}.png",
        ],
    )
    for path in candidates:
        if path.is_file():
            return path
    return None


def _copy_icon(src: Path, dest: Path) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size == src.stat().st_size:
        # Same size is a cheap idempotency check for our static branding assets.
        if dest.read_bytes() == src.read_bytes():
            return False
    shutil.copy2(src, dest)
    return True


def install_user_icons() -> dict[str, Any]:
    """Install hicolor theme icons under ``~/.local/share/icons``."""
    if is_flatpak():
        return {"ok": True, "skipped": True, "message": "Flatpak ships icons in /app/share/icons"}
    branding = branding_dir()
    if not branding.is_dir():
        return {"ok": False, "message": f"branding directory missing: {branding}"}
    root = user_icons_root()
    copied = 0
    for size in ICON_SIZES:
        src = branding / "hicolor" / f"{size}x{size}" / "apps" / f"{ICON_NAME}.png"
        if not src.is_file() and size == 512:
            src = branding / "oysterAV-icon.png"
        if not src.is_file():
            continue
        dest = root / f"{size}x{size}" / "apps" / f"{ICON_NAME}.png"
        if _copy_icon(src, dest):
            copied += 1
    cache = shutil.which("gtk-update-icon-cache")
    if cache:
        subprocess.run(
            [cache, "-f", str(root)],
            check=False,
            capture_output=True,
            text=True,
        )
    return {
        "ok": True,
        "copied": copied,
        "icon_name": ICON_NAME,
        "path": str(root),
        "message": f"Icons installed under {root} ({copied} updated)",
    }


def install_user_launcher() -> dict[str, Any]:
    """Install applications-menu .desktop (Icon=oysterav, StartupWMClass)."""
    if is_flatpak():
        return {
            "ok": True,
            "skipped": True,
            "message": "Flatpak exports the .desktop on install",
        }
    path = user_launcher_path()
    entry = build_desktop_entry(minimized=False, for_autostart=False)
    previous = path.read_text(encoding="utf-8") if path.is_file() else ""
    changed = previous != entry
    if changed:
        path.write_text(entry, encoding="utf-8")
    updater = shutil.which("update-desktop-database")
    if updater:
        subprocess.run(
            [updater, str(user_applications_dir())],
            check=False,
            capture_output=True,
            text=True,
        )
    return {
        "ok": True,
        "changed": changed,
        "path": str(path),
        "message": f"Launcher {'updated' if changed else 'unchanged'} at {path}",
    }


def remove_user_launcher() -> dict[str, Any]:
    path = user_launcher_path()
    existed = path.is_file()
    path.unlink(missing_ok=True)
    return {
        "ok": True,
        "removed": existed,
        "path": str(path),
        "message": "Launcher removed" if existed else "Launcher was not present",
    }


def ensure_desktop_integration() -> dict[str, Any]:
    """Idempotent icons + applications launcher for unpackaged / uv runs."""
    icons = install_user_icons()
    launcher = install_user_launcher()
    ok = bool(icons.get("ok")) and bool(launcher.get("ok"))
    return {
        "ok": ok,
        "icons": icons,
        "launcher": launcher,
        "message": "Desktop icons and launcher ready" if ok else "Desktop integration incomplete",
    }


def desktop_integration_status() -> dict[str, Any]:
    launcher = user_launcher_path()
    icon_present = any(
        (user_icons_root() / f"{size}x{size}" / "apps" / f"{ICON_NAME}.png").is_file()
        for size in ICON_SIZES
    )
    return {
        "icon_name": ICON_NAME,
        "user_icons_installed": icon_present,
        "user_icons_root": str(user_icons_root()),
        "launcher_path": str(launcher),
        "launcher_present": launcher.is_file(),
        "branding_dir": str(branding_dir()),
        "branding_present": branding_dir().is_dir(),
        "flatpak": is_flatpak(),
    }


__all__ = [
    "ICON_NAME",
    "ICON_SIZES",
    "branding_dir",
    "desktop_integration_status",
    "ensure_desktop_integration",
    "install_user_icons",
    "install_user_launcher",
    "remove_user_launcher",
    "resolve_icon_png",
    "user_launcher_path",
]
