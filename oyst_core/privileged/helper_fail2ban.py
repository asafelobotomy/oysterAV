"""Fail2ban + ignoreip builders for oyst-helper."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.helper_firewall import _has_flag, _parse_flag
from oyst_core.privileged.helper_validate import resolve_trusted_argv
from oyst_core.privileged.safe_write import write_text_nofollow
from oyst_core.privileged.validators import validate_ip, validate_jail


def _secure_exec_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def _run_fail2ban_client(argv: list[str]) -> None:
    """Run fail2ban-client as root; raise ValueError on failure."""
    cmd = resolve_trusted_argv(list(argv))
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        env=_secure_exec_env(),
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "fail2ban-client failed").strip()
        raise ValueError(detail)


_JAIL_D = Path("/etc/fail2ban/jail.d")
_DROPIN_MAX_BYTES = 64 * 1024


def _read_dropin_nofollow(path: Path) -> str:
    """Return a regular, non-symlink drop-in's text ('' when absent/unsafe)."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        data = os.read(fd, _DROPIN_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _DROPIN_MAX_BYTES:
        return ""
    return data.decode("utf-8", errors="replace")


def _existing_ignoreips(path: Path) -> list[str]:
    """IPs already persisted in our drop-in; each re-validated, invalid ones dropped."""
    found: list[str] = []
    for line in _read_dropin_nofollow(path).splitlines():
        key, sep, value = line.partition("=")
        if not sep or key.strip().lower() != "ignoreip":
            continue
        for token in value.replace(",", " ").split():
            try:
                found.append(validate_ip(token))
            except ValueError:
                continue
    return found


def _persist_fail2ban_ignoreip(jail: str, ip: str) -> None:
    if jail.upper() == "DEFAULT":
        raise ValueError("refusing to override the DEFAULT jail ignoreip")
    if any(ch in f"{jail}{ip}" for ch in "\r\n[]=#;"):
        raise ValueError("invalid characters in fail2ban persist arguments")
    ip = validate_ip(ip)
    dropin_dir = _JAIL_D
    dropin_dir.mkdir(parents=True, exist_ok=True)
    dropin = dropin_dir / f"oysterav-{jail}-ignore.conf"
    merged = list(dict.fromkeys([*_existing_ignoreips(dropin), ip]))
    write_text_nofollow(dropin, f"[{jail}]\nignoreip = {' '.join(merged)}\n", mode=0o644)
    _run_fail2ban_client(["fail2ban-client", "reload"])


def _build_fail2ban_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("fail2ban action required")
    action = argv[0]
    rest = list(argv[1:])
    if action == "banned":
        return ["fail2ban-client", "banned"]
    if action == "unban":
        if not rest:
            raise ValueError("IP required")
        return ["fail2ban-client", "unban", validate_ip(rest[0])]
    if action == "unbanip":
        if len(rest) < 2:
            raise ValueError("usage: unbanip <jail> <ip>")
        return [
            "fail2ban-client",
            "set",
            validate_jail(rest[0]),
            "unbanip",
            validate_ip(rest[1]),
        ]
    if action == "addignoreip":
        if len(rest) < 2:
            raise ValueError("usage: addignoreip <jail> <ip>")
        return [
            "fail2ban-client",
            "set",
            validate_jail(rest[0]),
            "addignoreip",
            validate_ip(rest[1]),
        ]
    if action == "jail-start":
        if not rest:
            raise ValueError("jail name required")
        return ["fail2ban-client", "start", validate_jail(rest[0])]
    if action == "jail-stop":
        if not rest:
            raise ValueError("jail name required")
        return ["fail2ban-client", "stop", validate_jail(rest[0])]
    if action == "reload":
        cmd = ["fail2ban-client", "reload"]
        if _has_flag(rest, "--unban"):
            cmd.append("--unban")
        return cmd
    if action == "persist-ignoreip":
        if len(rest) < 2:
            raise ValueError("usage: persist-ignoreip <jail> <ip>")
        jail = validate_jail(rest[0])
        ip = validate_ip(rest[1])
        _persist_fail2ban_ignoreip(jail, ip)
        return ["true"]
    if action == "unban-flow":
        # One polkit auth: unban, optional ignore, optional persist+reload.
        # usage: unban-flow <ip> [--jail NAME] [--ignore] [--persist]
        if not rest:
            raise ValueError("IP required")
        ip = validate_ip(rest[0])
        rem = list(rest[1:])
        jail_opt, rem = _parse_flag(rem, "--jail")
        ignore = _has_flag(rem, "--ignore")
        persist = _has_flag(rem, "--persist")
        rem = [a for a in rem if a not in ("--ignore", "--persist")]
        if rem:
            raise ValueError(f"unexpected unban-flow args: {' '.join(rem)}")
        if (ignore or persist) and not jail_opt:
            raise ValueError("--ignore/--persist require --jail")
        if jail_opt:
            jail_name = validate_jail(jail_opt)
            _run_fail2ban_client(["fail2ban-client", "set", jail_name, "unbanip", ip])
            if ignore:
                _run_fail2ban_client(["fail2ban-client", "set", jail_name, "addignoreip", ip])
            if persist:
                _persist_fail2ban_ignoreip(jail_name, ip)
        else:
            _run_fail2ban_client(["fail2ban-client", "unban", ip])
        return ["true"]
    raise ValueError(f"unknown fail2ban action: {action}")
