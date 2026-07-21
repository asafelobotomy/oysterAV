"""Secure subprocess execution."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


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
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    )
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.setdefault("PATH", "/usr/bin:/usr/sbin:/bin:/sbin")
    return env


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
    env = pkexec_scrubbed_env() if base in ("pkexec", "oyst-helper") else None
    proc = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
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
        timeout=timeout,
        check=False,
        input=input_text,
        cwd=cwd,
    )
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, list(argv), proc.stdout, proc.stderr)
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def parse_version(text: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in text.replace("_", ".").split():
        for piece in token.split("."):
            if piece.isdigit():
                parts.append(int(piece))
                break
    return tuple(parts) if parts else (0,)


def version_gte(found: str | None, minimum: str) -> bool:
    if not found:
        return False
    f = parse_version(found)
    m = parse_version(minimum)
    length = max(len(f), len(m))
    f_pad = f + (0,) * (length - len(f))
    m_pad = m + (0,) * (length - len(m))
    return f_pad >= m_pad
