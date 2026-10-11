"""Secure subprocess execution."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    # "cancel" / "timeout" when run_command_cancellable stopped the process.
    stopped: str | None = None


ALLOWED_COMMANDS = frozenset(
    {
        "clamscan",
        "clamdscan",
        "clamd",
        "freshclam",
        "clamonacc",
        "fangfrisch",
        "rkhunter",
        "chkrootkit",
        "lynis",
        "maldet",
        "ufw",
        "firewall-cmd",
        "nft",
        "fail2ban-client",
        "unhide",
        "unhide-linux",
        "systemctl",
        "pgrep",
        "pkill",
        "loginctl",
        "flatpak-spawn",
        "pacman",
        "paru",
        "yay",
    }
)

INSTALL_ALLOWED_COMMANDS = frozenset(
    {
        "pkexec",
        "apt",
        "apt-get",
        "pacman",
        "dnf",
        "paru",
        "yay",
        "loginctl",
        "oyst-helper",
    }
)


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def _command_basename(argv: Sequence[str]) -> str:
    if not argv:
        raise ValueError("empty argv")
    base = argv[0]
    if base == "pkexec":
        if len(argv) < 2:
            raise ValueError("pkexec requires a command")
        inner = argv[1]
        if inner.endswith("/oyst-helper") or inner == "oyst-helper":
            return "oyst-helper"
        return os.path.basename(inner)
    return os.path.basename(base)


def _resolve_install_base(argv: Sequence[str]) -> str:
    return _command_basename(argv)


def pkexec_scrubbed_env() -> dict[str, str]:
    """Minimal env for pkexec so session secrets are not inherited."""
    keep = (
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    )
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
    return env


def command_scrubbed_env() -> dict[str, str]:
    """Minimal env for allowlisted run_command children (no session secrets)."""
    keep = ("LANG", "LC_ALL", "LC_CTYPE", "TZ")
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
    return env


def user_session_scrubbed_env() -> dict[str, str]:
    """Scrubbed env that can reach the caller's systemd/D-Bus user session.

    Needed for ``systemctl --user`` (schedule timers). Still omits secrets;
    synthesizes ``XDG_RUNTIME_DIR`` / bus address from ``/run/user/<uid>`` when
    the parent process dropped those variables but the sockets exist.
    """
    env = command_scrubbed_env()
    for key in (
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "USER",
        "HOME",
        "LOGNAME",
    ):
        val = os.environ.get(key)
        if val:
            env[key] = val

    uid = os.getuid()
    runtime = env.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
    if "XDG_RUNTIME_DIR" not in env and os.path.isdir(runtime):
        env["XDG_RUNTIME_DIR"] = runtime
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus_path = os.path.join(env.get("XDG_RUNTIME_DIR", runtime), "bus")
        if os.path.exists(bus_path):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"
    if "HOME" not in env:
        env["HOME"] = os.path.expanduser("~")
    if "USER" not in env:
        try:
            import pwd

            env["USER"] = pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    return env


def _argv_needs_user_session(argv: Sequence[str]) -> bool:
    """True when argv talks to the user systemd manager (needs session bus)."""
    for index, arg in enumerate(argv):
        if os.path.basename(arg) != "systemctl":
            continue
        return "--user" in argv[index + 1 :]
    return False


def scrubbed_env_for_argv(argv: Sequence[str]) -> dict[str, str]:
    """Pick scrubbed env for an allowlisted command argv."""
    if _argv_needs_user_session(argv):
        return user_session_scrubbed_env()
    return command_scrubbed_env()


def run_install_command(
    argv: Sequence[str],
    *,
    timeout: int = 3600,
    cwd: str | None = None,
) -> CommandResult:
    """Run a package-manager install command (pkexec-wrapped or direct)."""
    base = _resolve_install_base(argv)
    if base not in INSTALL_ALLOWED_COMMANDS:
        raise ValueError(f"install command not allowlisted: {base}")
    env = pkexec_scrubbed_env() if base in ("pkexec", "oyst-helper") else command_scrubbed_env()
    proc = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        # Non-UTF-8 bytes (e.g. filenames in scanner output) must not raise and
        # discard a whole scan's results; keep them visible as \xNN escapes.
        errors="backslashreplace",
        timeout=timeout,
        check=False,
        cwd=cwd,
        env=env,
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def run_command(
    argv: Sequence[str],
    *,
    timeout: int = 3600,
    check: bool = False,
    input_text: str | None = None,
    cwd: str | None = None,
) -> CommandResult:
    if not argv:
        raise ValueError("empty argv")
    base = _command_basename(argv)
    if base not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowlisted: {base}")
    proc = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        # Non-UTF-8 bytes (e.g. filenames in scanner output) must not raise and
        # discard a whole scan's results; keep them visible as \xNN escapes.
        errors="backslashreplace",
        timeout=timeout,
        check=False,
        input=input_text,
        cwd=cwd,
        env=scrubbed_env_for_argv(argv),
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, list(argv), proc.stdout, proc.stderr)
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def run_command_cancellable(
    argv: Sequence[str],
    *,
    timeout: int = 3600,
    should_cancel: Callable[[], bool] | None = None,
    poll: float = 1.0,
    grace: float = 5.0,
) -> CommandResult:
    """Like run_command, but stoppable mid-run; keeps output read so far.

    On cancel or timeout the process gets SIGTERM, then SIGKILL after
    ``grace`` seconds. ``stopped`` on the result says why it ended early.
    """
    if not argv:
        raise ValueError("empty argv")
    base = _command_basename(argv)
    if base not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowlisted: {base}")
    proc = subprocess.Popen(  # noqa: S603 — allowlisted argv, no shell
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="backslashreplace",
        env=scrubbed_env_for_argv(argv),
    )
    deadline = time.monotonic() + timeout
    stopped: str | None = None
    while stopped is None:
        try:
            # Retrying communicate() after TimeoutExpired loses no output.
            out, err = proc.communicate(timeout=poll)
            return CommandResult(proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            pass
        if should_cancel is not None and should_cancel():
            stopped = "cancel"
        elif time.monotonic() >= deadline:
            stopped = "timeout"
    proc.terminate()
    try:
        out, err = proc.communicate(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return CommandResult(proc.returncode, out or "", err or "", stopped=stopped)


_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def parse_version(text: str) -> tuple[int, ...]:
    """First dotted number in ``text``: ``"ClamAV 1.5.4-1"`` -> ``(1, 5, 4)``."""
    match = _VERSION_RE.search(text.replace("_", "."))
    if not match:
        return (0,)
    return tuple(int(piece) for piece in match.group(0).split("."))


def version_gte(found: str | None, minimum: str) -> bool:
    if not found:
        return False
    f = parse_version(found)
    m = parse_version(minimum)
    length = max(len(f), len(m))
    f_pad = f + (0,) * (length - len(f))
    m_pad = m + (0,) * (length - len(m))
    return f_pad >= m_pad
