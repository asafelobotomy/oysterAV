"""Systemd user linger helpers and Flatpak/cli path resolution."""

from __future__ import annotations

import sys
from pathlib import Path

from oyst_core.privileged.runner import run_command, which


def is_flatpak() -> bool:
    return Path("/.flatpak-info").exists()


def resolve_oyst_cli_path() -> str | None:
    """Resolve absolute path to oyst-cli for systemd units."""
    candidates: list[str] = []
    found = which("oyst-cli")
    if found:
        candidates.append(found)
    exe = Path(sys.executable)
    venv_cli = exe.parent / "oyst-cli"
    if venv_cli.is_file():
        candidates.append(str(venv_cli))
    home_local = Path.home() / ".local" / "bin" / "oyst-cli"
    if home_local.is_file():
        candidates.append(str(home_local))
    for path in ("/usr/bin/oyst-cli", "/usr/local/bin/oyst-cli"):
        if Path(path).is_file():
            candidates.append(path)
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    return None


def get_linger_status() -> dict[str, object]:
    """Return whether user lingering is enabled for timer persistence."""
    import getpass

    user = getpass.getuser()
    res = run_command(["loginctl", "show-user", user, "-p", "Linger"], timeout=15)
    linger = "Linger=yes" in (res.stdout or "")
    return {
        "user": user,
        "linger": linger,
        "enable_hint": f"loginctl enable-linger {user}",
    }


def enable_linger() -> dict[str, object]:
    """Enable lingering for the current user (requires root)."""
    import getpass

    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.helper import run_privileged_linger

    user = getpass.getuser()
    res = run_privileged_linger(user)
    ok = res.returncode == 0
    status = get_linger_status()
    SecurityAudit().log("schedule.enable_linger", "enable", success=ok)
    return {
        "ok": ok,
        "message": (res.stderr or res.stdout or "").strip()[:300],
        "linger": status.get("linger", False),
    }


def disable_linger() -> dict[str, object]:
    """Disable lingering for the current user (requires root via oyst-helper)."""
    import getpass

    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.helper import run_privileged_linger_disable

    user = getpass.getuser()
    res = run_privileged_linger_disable(user)
    ok = res.returncode == 0
    status = get_linger_status()
    SecurityAudit().log("schedule.disable_linger", "disable", success=ok)
    return {
        "ok": ok,
        "message": (res.stderr or res.stdout or "").strip()[:300] or ("ok" if ok else "failed"),
        "linger": status.get("linger", False),
    }
