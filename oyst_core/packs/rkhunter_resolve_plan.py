"""Plan and validate rkhunter Resolve (whitelist) directives."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

OVERLAY_PATH = Path("/etc/rkhunter.d/oysterav-whitelist.conf")
OVERLAY_HEADER = "# oysterAV managed — do not edit by hand unless you know why\n"

RESOLVABLE_THREATS = frozenset(
    {
        "rkhunter-script-replacement",
        "rkhunter-hidden",
        "rkhunter-ssh",
    }
)

_MULTI_VALUE_OPTIONS = frozenset({"SCRIPTWHITELIST", "ALLOWHIDDENFILE"})
_SINGLE_VALUE_OPTIONS = frozenset({"ALLOW_SSH_PROT_V1", "ALLOW_SSH_ROOT_USER"})
ALLOWED_OPTIONS = _MULTI_VALUE_OPTIONS | _SINGLE_VALUE_OPTIONS

_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_SSH_PROT_VALUES = frozenset({"2"})
_SSH_ROOT_VALUES = frozenset({"unset"})

# systemd-update-done stamp files are not package-owned but are expected.
KNOWN_SAFE_HIDDEN = frozenset(
    {
        "/etc/.updated",
        "/var/.updated",
    }
)


@dataclass(frozen=True)
class ResolvePlan:
    threat_name: str
    option: str
    value: str
    explanation: str
    requires_path: bool


def is_resolvable_threat(threat_name: str) -> bool:
    return threat_name in RESOLVABLE_THREATS


def validate_whitelist_option(option: str, value: str) -> tuple[str, str]:
    """Validate option/value for helper writes. Raises ValueError on reject."""
    opt = option.strip()
    val = value.strip()
    if opt not in ALLOWED_OPTIONS:
        raise ValueError(f"option not allowlisted: {option}")
    if opt in _MULTI_VALUE_OPTIONS:
        if not _PATH_RE.match(val):
            raise ValueError(f"invalid whitelist path: {value}")
        return opt, val
    if opt == "ALLOW_SSH_PROT_V1":
        if val not in _SSH_PROT_VALUES:
            raise ValueError(f"invalid ALLOW_SSH_PROT_V1 value: {value}")
        return opt, val
    if opt == "ALLOW_SSH_ROOT_USER":
        if val not in _SSH_ROOT_VALUES:
            raise ValueError(f"invalid ALLOW_SSH_ROOT_USER value: {value}")
        return opt, val
    raise ValueError(f"option not allowlisted: {option}")


def require_abs_path(path: str) -> str:
    cleaned = path.strip()
    if not cleaned or cleaned == "system":
        raise ValueError("absolute path required")
    if not _PATH_RE.match(cleaned):
        raise ValueError(f"invalid path: {path}")
    return cleaned


def _require_abs_path(path: str) -> str:
    return require_abs_path(path)


def plan_resolve(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
) -> ResolvePlan:
    """Map a finding to a single overlay directive."""
    threat = threat_name.strip()
    if threat not in RESOLVABLE_THREATS:
        raise ValueError(f"threat not resolvable: {threat_name}")

    if threat == "rkhunter-script-replacement":
        cleaned = require_abs_path(path)
        return ResolvePlan(
            threat_name=threat,
            option="SCRIPTWHITELIST",
            value=cleaned,
            explanation=(
                f"Whitelist package-owned script {cleaned} in rkhunter "
                f"(SCRIPTWHITELIST). This does not change the file; it only "
                f"stops rkhunter treating a known distro wrapper as a warning."
            ),
            requires_path=True,
        )

    if threat == "rkhunter-hidden":
        cleaned = require_abs_path(path)
        return ResolvePlan(
            threat_name=threat,
            option="ALLOWHIDDENFILE",
            value=cleaned,
            explanation=(
                f"Allow hidden file {cleaned} in rkhunter (ALLOWHIDDENFILE). "
                f"This does not delete or modify the file."
            ),
            requires_path=True,
        )

    # rkhunter-ssh
    lower = message.lower()
    if "protocol" in lower:
        return ResolvePlan(
            threat_name=threat,
            option="ALLOW_SSH_PROT_V1",
            value="2",
            explanation=(
                "Tell rkhunter that an unset SSH Protocol option is acceptable "
                "(ALLOW_SSH_PROT_V1=2). Modern OpenSSH only supports protocol 2; "
                "this does not edit sshd_config."
            ),
            requires_path=False,
        )
    if "permitrootlogin" in lower:
        return ResolvePlan(
            threat_name=threat,
            option="ALLOW_SSH_ROOT_USER",
            value="unset",
            explanation=(
                "Tell rkhunter that an unset PermitRootLogin option is acceptable "
                "(ALLOW_SSH_ROOT_USER=unset). OpenSSH still applies its default; "
                "this does not edit sshd_config. Harden SSH separately if desired."
            ),
            requires_path=False,
        )
    raise ValueError(f"unrecognized SSH finding message: {message[:120]}")


def package_owner(path: str) -> str | None:
    """Return owning package name if a supported package manager reports one."""
    target = Path(path)
    checkers: list[list[str]] = []
    if shutil.which("pacman"):
        checkers.append(["pacman", "-Qo", "--", str(target)])
    if shutil.which("rpm"):
        checkers.append(["rpm", "-qf", str(target)])
    if shutil.which("dpkg"):
        checkers.append(["dpkg", "-S", str(target)])
    for argv in checkers:
        try:
            proc = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        text = (proc.stdout or proc.stderr or "").strip()
        if text:
            return text.splitlines()[0][:200]
    return None


def path_allowed_for_resolve(path: str, threat_name: str, *, force: bool = False) -> None:
    """Raise ValueError if path must not be whitelisted without --force."""
    cleaned = require_abs_path(path)
    p = Path(cleaned)
    if not p.exists():
        raise ValueError(f"path does not exist: {cleaned}")
    if force:
        return
    if threat_name == "rkhunter-hidden" and cleaned in KNOWN_SAFE_HIDDEN:
        return
    owner = package_owner(cleaned)
    if owner is None:
        raise ValueError(f"path is not package-owned (refusing without --force): {cleaned}")
