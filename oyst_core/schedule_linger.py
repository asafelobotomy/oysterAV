"""Systemd user linger helpers and Flatpak/cli path resolution."""

from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path

from oyst_core.privileged.runner import run_command, which

_TRUSTED_BIN_PREFIXES = ("/usr/bin/", "/usr/local/bin/")


def is_flatpak() -> bool:
    return Path("/.flatpak-info").exists()


def _is_root_owned_system_bin(path: Path) -> bool:
    try:
        resolved = path.resolve()
        st = resolved.stat()
    except OSError:
        return False
    if st.st_uid != 0:
        return False
    return str(resolved).startswith(_TRUSTED_BIN_PREFIXES)


def current_username() -> str:
    """Return the username for the real UID (ignore LOGNAME/USER spoofing)."""
    return pwd.getpwuid(os.getuid()).pw_name


def resolve_oyst_cli_path(*, for_elevation: bool = False) -> str | None:
    """Resolve absolute path to oyst-cli.

    Elevation (pkexec) only accepts root-owned ``/usr/bin`` or ``/usr/local/bin``.
    User timers prefer system paths, then the active venv, then ``~/.local`` —
    never PATH-first ``which``.
    """
    system: list[str] = []
    for system_path in ("/usr/bin/oyst-cli", "/usr/local/bin/oyst-cli"):
        system_file = Path(system_path)
        if not system_file.is_file():
            continue
        if for_elevation and not _is_root_owned_system_bin(system_file):
            continue
        system.append(str(system_file.resolve()))
    if for_elevation:
        return system[0] if system else None

    candidates = list(system)
    venv_cli = Path(sys.executable).resolve().parent / "oyst-cli"
    if venv_cli.is_file():
        candidates.append(str(venv_cli))
    home_local = Path.home() / ".local" / "bin" / "oyst-cli"
    if home_local.is_file():
        candidates.append(str(home_local.resolve()))
    found = which("oyst-cli")
    if found:
        candidates.append(found)
    for cli_path in candidates:
        if Path(cli_path).is_file():
            return cli_path
    return None


def escape_systemd_exec_arg(path: str) -> str:
    """Quote a path for systemd ExecStart; reject % and control characters."""
    if any(ch in path for ch in ("\n", "\r", "\0", "%")):
        raise ValueError("cli path contains disallowed characters for systemd ExecStart")
    if any(ch in path for ch in ('"', "\\", " ", "\t")):
        escaped = path.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return path


def get_linger_status() -> dict[str, object]:
    """Return whether user lingering is enabled for timer persistence."""
    user = current_username()
    res = run_command(["loginctl", "show-user", user, "-p", "Linger"], timeout=15)
    linger = "Linger=yes" in (res.stdout or "")
    return {
        "user": user,
        "linger": linger,
        "enable_hint": f"loginctl enable-linger {user}",
    }


def enable_linger() -> dict[str, object]:
    """Enable lingering for the current user (requires root)."""
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.helper import run_privileged_linger

    user = current_username()
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
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.helper import run_privileged_linger_disable

    user = current_username()
    res = run_privileged_linger_disable(user)
    ok = res.returncode == 0
    status = get_linger_status()
    SecurityAudit().log("schedule.disable_linger", "disable", success=ok)
    return {
        "ok": ok,
        "message": (res.stderr or res.stdout or "").strip()[:300] or ("ok" if ok else "failed"),
        "linger": status.get("linger", False),
    }
