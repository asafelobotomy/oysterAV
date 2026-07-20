"""Probe host clamd.conf for OnAccessPrevention (ADR-008 Phase 1)."""

from __future__ import annotations

import gzip
import os
import re
from pathlib import Path
from typing import Literal

Classification = Literal[
    "impossible",
    "notify_only",
    "block_misconfigured",
    "blocking",
    "handoff_required",
]

# Distro hints only — verify existence at probe time (ADR-008).
_CONF_CANDIDATES = (
    Path("/etc/clamav/clamd.conf"),
    Path("/etc/clamd.d/scan.conf"),
    Path("/etc/clamd.conf"),
)

_KEY_RE = re.compile(
    r"^(?P<key>[A-Za-z][A-Za-z0-9]*)\s+(?P<value>.+?)\s*$",
)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"yes", "true", "1", "on"}


def parse_clamd_conf(text: str) -> dict[str, object]:
    """Parse selected OnAccess / User / Harden keys from a clamd conf body."""
    prevention: bool | None = None
    user: str | None = None
    include_paths: list[str] = []
    mount_paths: list[str] = []
    exclude_unames: list[str] = []
    disable_cache: bool | None = None
    local_socket: str | None = None

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _KEY_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value").strip()
        key_l = key.lower()
        if key_l == "onaccessprevention":
            prevention = _truthy(value)
        elif key_l == "user":
            user = value
        elif key_l == "onaccessincludepath":
            include_paths.append(value)
        elif key_l == "onaccessmountpath":
            mount_paths.append(value)
        elif key_l == "onaccessexcludeuname":
            exclude_unames.append(value)
        elif key_l == "disablecache":
            disable_cache = _truthy(value)
        elif key_l == "localsocket":
            local_socket = value

    return {
        "prevention": prevention,
        "user": user,
        "include_paths": include_paths,
        "mount_paths": mount_paths,
        "exclude_unames": exclude_unames,
        "disable_cache": disable_cache,
        "local_socket": local_socket,
    }


def list_conf_conflict_sidecars(conf: Path) -> list[str]:
    """Return package upgrade sidecars next to conf (``.rpmnew``, ``.dpkg-dist``, …)."""
    found: list[str] = []
    for suffix in (".rpmnew", ".dpkg-dist", ".ucf-dist", ".dpkg-old"):
        side = Path(str(conf) + suffix)
        try:
            if side.is_file():
                found.append(str(side))
        except OSError:
            continue
    return found


def discover_clamd_conf_paths(*, extra: list[Path] | None = None) -> list[Path]:
    """Return readable candidate conf paths (first match is preferred)."""
    found: list[Path] = []
    for path in (*(extra or ()), *_CONF_CANDIDATES):
        try:
            if path.is_file() and os.access(path, os.R_OK):
                found.append(path.resolve())
        except OSError:
            continue
    # Dedupe while preserving order.
    seen: set[Path] = set()
    out: list[Path] = []
    for path in found:
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def fanotify_access_permissions_enabled() -> bool | None:
    """True/False when kernel config is readable; None if unknown."""
    uname = os.uname().release
    candidates: list[Path] = [
        Path(f"/boot/config-{uname}"),
        Path("/proc/config.gz"),
    ]
    for path in candidates:
        try:
            if not path.is_file():
                continue
            if path.suffix == ".gz" or path.name.endswith(".gz"):
                text = gzip.open(path, "rt", encoding="utf-8", errors="replace").read()
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fanotify = "CONFIG_FANOTIFY=y" in text
        access = "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y" in text
        if fanotify and access:
            return True
        if "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=n" in text or (
            fanotify and "CONFIG_FANOTIFY_ACCESS_PERMISSIONS" not in text
        ):
            return False
        if "CONFIG_FANOTIFY=n" in text:
            return False
    return None


def classify_onaccess(
    parsed: dict[str, object],
    *,
    kernel_ok: bool | None,
) -> Classification:
    """Classify host blocking capability from parsed conf + optional kernel probe."""
    if kernel_ok is False:
        return "impossible"

    prevention = parsed.get("prevention")
    mount_paths = parsed.get("mount_paths")
    if not isinstance(mount_paths, list):
        mount_paths = []

    if prevention is True:
        if mount_paths:
            return "block_misconfigured"
        return "blocking"

    return "notify_only"


def probe_onaccess_prevention(
    *,
    conf_paths: list[Path] | None = None,
    kernel_ok: bool | None = None,
) -> dict[str, object]:
    """
    Discover and classify host OnAccessPrevention.

    oysterAV never writes clamd.conf; this probe only reports host truth (ADR-008).
    """
    if kernel_ok is None:
        kernel_ok = fanotify_access_permissions_enabled()

    paths = conf_paths if conf_paths is not None else discover_clamd_conf_paths()
    if not paths:
        return {
            "classification": "handoff_required",
            "prevention_enforced": False,
            "conf_path": None,
            "kernel_access_permissions": kernel_ok,
            "prevention": None,
            "include_paths": [],
            "mount_paths": [],
            "exclude_unames": [],
            "user": None,
            "disable_cache": None,
            "local_socket": None,
            "conflict_sidecars": [],
            "error": "no readable clamd conf among candidates",
        }

    if kernel_ok is False:
        sidecars = list_conf_conflict_sidecars(paths[0])
        return {
            "classification": "impossible",
            "prevention_enforced": False,
            "conf_path": str(paths[0]),
            "kernel_access_permissions": False,
            "prevention": None,
            "include_paths": [],
            "mount_paths": [],
            "exclude_unames": [],
            "user": None,
            "disable_cache": None,
            "local_socket": None,
            "conflict_sidecars": sidecars,
            "error": None,
        }

    # Prefer the first readable conf that mentions OnAccess* or User.
    chosen: Path | None = None
    parsed: dict[str, object] = {
        "prevention": None,
        "user": None,
        "include_paths": [],
        "mount_paths": [],
        "exclude_unames": [],
        "disable_cache": None,
        "local_socket": None,
    }
    last_error: str | None = None
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            last_error = str(exc)
            continue
        candidate = parse_clamd_conf(text)
        chosen = path
        parsed = candidate
        # Prefer a file that explicitly sets prevention or include paths.
        if candidate.get("prevention") is not None or candidate.get("include_paths"):
            break

    if chosen is None:
        return {
            "classification": "handoff_required",
            "prevention_enforced": False,
            "conf_path": None,
            "kernel_access_permissions": kernel_ok,
            "prevention": None,
            "include_paths": [],
            "mount_paths": [],
            "exclude_unames": [],
            "user": None,
            "disable_cache": None,
            "local_socket": None,
            "conflict_sidecars": [],
            "error": last_error or "unreadable clamd conf",
        }

    classification = classify_onaccess(parsed, kernel_ok=kernel_ok)
    include_raw = parsed.get("include_paths")
    mount_raw = parsed.get("mount_paths")
    exclude_raw = parsed.get("exclude_unames")
    include_paths = [str(p) for p in include_raw] if isinstance(include_raw, list) else []
    mount_paths = [str(p) for p in mount_raw] if isinstance(mount_raw, list) else []
    exclude_unames = [str(p) for p in exclude_raw] if isinstance(exclude_raw, list) else []
    return {
        "classification": classification,
        "prevention_enforced": classification == "blocking",
        "conf_path": str(chosen),
        "kernel_access_permissions": kernel_ok,
        "prevention": parsed.get("prevention"),
        "include_paths": include_paths,
        "mount_paths": mount_paths,
        "exclude_unames": exclude_unames,
        "user": parsed.get("user"),
        "disable_cache": parsed.get("disable_cache"),
        "local_socket": parsed.get("local_socket"),
        "conflict_sidecars": list_conf_conflict_sidecars(chosen),
        "error": None,
    }
