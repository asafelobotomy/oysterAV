"""Elevate allowlisted oyst-cli commands via pkexec (Polkit password prompt).

Used by GUI/RPC for helper install and auth grant/revoke without spawning
tools from oysterav/. Does not use oyst-helper (chicken-and-egg for install).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.runner import (
    CommandResult,
    command_scrubbed_env,
    pkexec_scrubbed_env,
    which,
)
from oyst_core.schedule_linger import is_flatpak, resolve_oyst_cli_path

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# Exact argv templates after the oyst-cli binary (optional trailing --json is added by caller).
_ALLOWED_BASE: frozenset[tuple[str, ...]] = frozenset(
    {
        ("install-privileged-helper",),
        ("auth", "grant-service-lifecycle"),
        ("auth", "revoke-service-lifecycle"),
    }
)


def _validate_elevated_argv(argv: Sequence[str]) -> list[str]:
    """Return a sanitized argv (without binary) or raise ValueError."""
    parts = [str(a) for a in argv]
    if not parts:
        raise ValueError("empty elevated argv")
    # Strip trailing --json / optional --confirm for base matching.
    want_json = False
    if parts[-1] == "--json":
        want_json = True
        parts = parts[:-1]
    parts = [p for p in parts if p != "--confirm"]
    user: str | None = None
    if len(parts) >= 4 and parts[0:2] == ["auth", "grant-service-lifecycle"]:
        if parts[2] != "--user" or len(parts) != 4:
            raise ValueError("invalid grant argv")
        user = parts[3]
        if not _USERNAME_RE.fullmatch(user):
            raise ValueError(f"invalid username: {user}")
        base: tuple[str, ...] = ("auth", "grant-service-lifecycle")
    else:
        base = tuple(parts)
        if base not in _ALLOWED_BASE:
            raise ValueError(f"elevated command not allowlisted: {' '.join(parts)}")
    out = list(base)
    if user is not None:
        out.extend(["--user", user])
    if base in {
        ("auth", "grant-service-lifecycle"),
        ("auth", "revoke-service-lifecycle"),
    }:
        out.append("--confirm")
    if want_json:
        out.append("--json")
    return out


def _host_oyst_cli_for_flatpak() -> str:
    """Prefer host package path when elevating from inside Flatpak."""
    for path in ("/usr/bin/oyst-cli", "/usr/local/bin/oyst-cli"):
        if Path(path).is_file():
            return path
    return "/usr/bin/oyst-cli"


def run_elevated_oyst_cli(
    argv: Sequence[str],
    *,
    timeout: int = 300,
) -> CommandResult:
    """Run ``pkexec <oyst-cli> <allowlisted argv>`` (or direct if already root).

    Inside Flatpak, uses ``flatpak-spawn --host pkexec …`` so Polkit runs on the host.
    Host ``oyst-cli`` must be installed (distro package) for chicken-egg bootstrap.
    """
    sanitized = _validate_elevated_argv(argv)
    if os.geteuid() == 0:
        cli = resolve_oyst_cli_path(for_elevation=True)
        if not cli:
            return CommandResult(
                1,
                "",
                "oyst-cli not found under root-owned /usr/bin or /usr/local/bin "
                "(required for elevation)",
            )
        cmd = [cli, *sanitized]
    elif is_flatpak():
        spawn = which("flatpak-spawn")
        if not spawn:
            return CommandResult(1, "", "flatpak-spawn required for Flatpak elevation")
        host_cli = _host_oyst_cli_for_flatpak()
        cmd = [spawn, "--host", "pkexec", host_cli, *sanitized]
    else:
        cli = resolve_oyst_cli_path(for_elevation=True)
        if not cli:
            return CommandResult(
                1,
                "",
                "oyst-cli not found under root-owned /usr/bin or /usr/local/bin "
                "(required for pkexec elevation)",
            )
        pkexec = which("pkexec")
        if not pkexec:
            return CommandResult(1, "", "pkexec required for privileged operation")
        cmd = [pkexec, cli, *sanitized]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=pkexec_scrubbed_env() if "pkexec" in cmd else command_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(1, "", str(exc))
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def _parse_json_result(res: CommandResult) -> dict[str, object]:
    text = (res.stdout or "").strip()
    if text:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    ok = res.returncode == 0
    msg = (res.stderr or res.stdout or "").strip() or ("ok" if ok else "failed")
    return {"ok": ok, "message": msg}


def install_helper_elevated() -> dict[str, object]:
    """Install oyst-helper + polkit policy via Polkit (or directly if root)."""
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.install_privileged_helper import (
        helper_status,
        install_privileged_helper,
    )

    if os.geteuid() == 0:
        result = install_privileged_helper()
    else:
        res = run_elevated_oyst_cli(["install-privileged-helper", "--json"])
        result = _parse_json_result(res)
        if res.returncode != 0 and "ok" not in result:
            result = {"ok": False, "message": result.get("message") or "install failed"}
    ok = bool(result.get("ok"))
    SecurityAudit().log("helper.install", "install", success=ok)
    status = helper_status()
    return {
        "ok": ok,
        "message": str(result.get("message") or ("ok" if ok else "failed")),
        "helper": status,
        "helper_path": result.get("helper_path") or status.get("helper_path"),
        "polkit_path": result.get("polkit_path") or status.get("polkit_path"),
    }


def grant_service_lifecycle_elevated(user: str | None = None) -> dict[str, object]:
    """Grant passwordless service-lifecycle via Polkit (or directly if root)."""
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.auth_grant import auth_status, grant_service_lifecycle
    from oyst_core.schedule_linger import current_username

    # Ignore caller-supplied user (confused-deputy); always grant for this UID.
    _ = user
    target = current_username()
    if os.geteuid() == 0:
        result = grant_service_lifecycle(target)
    else:
        res = run_elevated_oyst_cli(
            ["auth", "grant-service-lifecycle", "--user", target, "--json"],
        )
        result = _parse_json_result(res)
    ok = bool(result.get("ok"))
    SecurityAudit().log("auth.grant", "grant-service-lifecycle", success=ok, data={"user": target})
    return {
        "ok": ok,
        "message": str(result.get("message") or ("ok" if ok else "failed")),
        "granted_user": result.get("granted_user") or (target if ok else None),
        "service_lifecycle": auth_status(),
    }


def revoke_service_lifecycle_elevated() -> dict[str, object]:
    """Revoke passwordless service-lifecycle via Polkit (or directly if root)."""
    from oyst_core.audit import SecurityAudit
    from oyst_core.privileged.auth_grant import auth_status, revoke_service_lifecycle

    if os.geteuid() == 0:
        result = revoke_service_lifecycle()
    else:
        res = run_elevated_oyst_cli(["auth", "revoke-service-lifecycle", "--json"])
        result = _parse_json_result(res)
    ok = bool(result.get("ok"))
    SecurityAudit().log("auth.revoke", "revoke-service-lifecycle", success=ok)
    return {
        "ok": ok,
        "message": str(result.get("message") or ("ok" if ok else "failed")),
        "service_lifecycle": auth_status(),
    }
