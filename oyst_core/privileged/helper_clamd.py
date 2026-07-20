"""ClamAV host conf co-control builders for oyst-helper (ADR-008 Phase 4/4.1)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from oyst_core.packs.clamd_onaccess import list_conf_conflict_sidecars
from oyst_core.privileged.helper_clamd_unit import (
    FDPASS_DROPIN_NAME,
    ensure_fdpass_dropin,
    restart_clam_stack,
)
from oyst_core.privileged.safe_write import write_text_nofollow

ONACCESS_BEGIN = "# oysterAV OnAccess begin"
ONACCESS_END = "# oysterAV OnAccess end"
VIRUSEVENT_BEGIN = "# oysterAV VirusEvent begin"
VIRUSEVENT_END = "# oysterAV VirusEvent end"
HARDEN_BEGIN = "# oysterAV Harden begin"
HARDEN_END = "# oysterAV Harden end"
OYSTERAV_MARK = "oyst-virusevent"

_CONF_RE = re.compile(r"^/etc/(clamav/|clamd\.d/)[A-Za-z0-9._+-]+\.conf$|^/etc/clamd\.conf$")
_WRAPPER_RE = re.compile(r"^/[A-Za-z0-9._/+-]+$")
_INCLUDE_RE = re.compile(r"^/[A-Za-z0-9._/+-]+$")
_UNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")

DENIED_INCLUDE_PREFIXES = (
    "/",
    "/usr",
    "/etc",
    "/var",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/run",
    "/root",
)


def _parse_flag(argv: Sequence[str], name: str) -> str | None:
    prefix = f"--{name}="
    for item in argv:
        if item.startswith(prefix):
            return item[len(prefix) :]
    return None


def _parse_multi(argv: Sequence[str], name: str) -> list[str]:
    prefix = f"--{name}="
    return [item[len(prefix) :] for item in argv if item.startswith(prefix)]


def _validate_conf_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"invalid conf path: {raw}")
    if not _CONF_RE.match(str(path)):
        raise ValueError(f"conf path not allowlisted: {raw}")
    if not path.is_file():
        raise ValueError(f"conf not found: {raw}")
    return path.resolve()


def _validate_wrapper_cmd(raw: str) -> str:
    cleaned = raw.strip()
    if not _WRAPPER_RE.match(cleaned) or OYSTERAV_MARK not in cleaned:
        raise ValueError("VirusEvent command must be absolute oysterAV wrapper path")
    if any(ch in cleaned for ch in (" ", ";", "|", "&", "`", "$", "\n", "\r")):
        raise ValueError("VirusEvent command must not contain shell metacharacters")
    return cleaned


def _validate_include(raw: str) -> str:
    cleaned = raw.strip()
    if not _INCLUDE_RE.match(cleaned) or ".." in Path(cleaned).parts:
        raise ValueError(f"invalid include path: {raw}")
    if cleaned == "/":
        raise ValueError("include path denied: /")
    for prefix in DENIED_INCLUDE_PREFIXES:
        if prefix == "/":
            continue
        if cleaned == prefix or cleaned.startswith(prefix + "/"):
            raise ValueError(f"include path denied: {raw}")
    return cleaned


def _validate_uname(raw: str) -> str:
    cleaned = raw.strip()
    if not _UNAME_RE.match(cleaned):
        raise ValueError(f"invalid OnAccessExcludeUname: {raw}")
    return cleaned


def _backup_conf(conf: Path) -> Path:
    backup = Path(str(conf) + ".oysterav-bak")
    write_text_nofollow(backup, conf.read_text(encoding="utf-8"), mode=0o644)
    return backup


def _replace_marked_block(text: str, begin: str, end: str, body_lines: list[str]) -> str:
    lines = text.splitlines()
    start_i: int | None = None
    end_i: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == begin:
            start_i = i
        elif line.strip() == end and start_i is not None:
            end_i = i
            break
    block = [begin, *body_lines, end]
    if start_i is not None and end_i is not None:
        return "\n".join([*lines[:start_i], *block, *lines[end_i + 1 :]]) + "\n"
    stripped = text.rstrip("\n")
    sep = "\n\n" if stripped else ""
    return stripped + sep + "\n".join(block) + "\n"


def _require_no_sidecars(conf: Path) -> None:
    conflicts = list_conf_conflict_sidecars(conf)
    if conflicts:
        raise ValueError(f"package conflict sidecars present: {', '.join(conflicts)}")


def _ensure_virusevent(conf: Path, cmd: str) -> None:
    _require_no_sidecars(conf)
    text = conf.read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "virusevent":
            value = parts[1].strip()
            if OYSTERAV_MARK not in value and cmd not in value:
                raise ValueError("foreign VirusEvent — hand off (do not overwrite)")
    _backup_conf(conf)
    updated = _replace_marked_block(
        text,
        VIRUSEVENT_BEGIN,
        VIRUSEVENT_END,
        [f"VirusEvent {cmd}"],
    )
    write_text_nofollow(conf, updated, mode=0o644)


def _ensure_prevention(conf: Path, uname: str, includes: list[str]) -> None:
    if not includes:
        raise ValueError("at least one --include= path required")
    _require_no_sidecars(conf)
    text = conf.read_text(encoding="utf-8")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) >= 1 and parts[0].lower() == "onaccessmountpath":
            raise ValueError("OnAccessMountPath present — hand off (incompatible with prevention)")
    body = [f"OnAccessIncludePath {p}" for p in includes]
    body.append("OnAccessPrevention yes")
    body.append(f"OnAccessExcludeUname {uname}")
    _backup_conf(conf)
    updated = _replace_marked_block(text, ONACCESS_BEGIN, ONACCESS_END, body)
    write_text_nofollow(conf, updated, mode=0o644)


def _ensure_disable_cache(conf: Path) -> None:
    """Surgical DisableCache yes when unset or oysterAV-marked; else handoff."""
    _require_no_sidecars(conf)
    text = conf.read_text(encoding="utf-8")
    in_harden = False
    foreign_no = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped == HARDEN_BEGIN:
            in_harden = True
            continue
        if stripped == HARDEN_END:
            in_harden = False
            continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "disablecache":
            val = parts[1].strip().lower()
            if val in {"no", "false", "0", "off"} and not in_harden:
                foreign_no = True
    if foreign_no:
        raise ValueError("foreign DisableCache no — hand off (do not overwrite)")
    _backup_conf(conf)
    updated = _replace_marked_block(text, HARDEN_BEGIN, HARDEN_END, ["DisableCache yes"])
    write_text_nofollow(conf, updated, mode=0o644)


def _socket_args(rest: Sequence[str]) -> list[str] | None:
    socks = _parse_multi(rest, "socket")
    return socks or None


def _build_clamd_cocontrol_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError(
            "usage: clamd-cocontrol ensure-fdpass|ensure-virusevent|"
            "ensure-prevention|ensure-disable-cache|restart-stack …",
        )
    action = argv[0]
    rest = list(argv[1:])
    sockets = _socket_args(rest)
    if action == "ensure-fdpass":
        unit = _parse_flag(rest, "unit") or "clamav-clamonacc"
        ensure_fdpass_dropin(unit)
        return ["true"]
    if action == "ensure-virusevent":
        conf_raw = _parse_flag(rest, "conf")
        cmd_raw = _parse_flag(rest, "cmd")
        if not conf_raw or not cmd_raw:
            raise ValueError("usage: ensure-virusevent --conf=PATH --cmd=WRAPPER")
        conf = _validate_conf_path(conf_raw)
        cmd = _validate_wrapper_cmd(cmd_raw)
        _ensure_virusevent(conf, cmd)
        restart_clam_stack(
            _parse_flag(rest, "clamd-unit"),
            _parse_flag(rest, "clamonacc-unit"),
            sockets=sockets,
        )
        return ["true"]
    if action == "ensure-prevention":
        conf_raw = _parse_flag(rest, "conf")
        uname_raw = _parse_flag(rest, "user")
        if not conf_raw or not uname_raw:
            raise ValueError(
                "usage: ensure-prevention --conf=PATH --user=NAME --include=PATH …",
            )
        conf = _validate_conf_path(conf_raw)
        uname = _validate_uname(uname_raw)
        includes = [_validate_include(p) for p in _parse_multi(rest, "include")]
        _ensure_prevention(conf, uname, includes)
        restart_clam_stack(
            _parse_flag(rest, "clamd-unit"),
            _parse_flag(rest, "clamonacc-unit"),
            sockets=sockets,
        )
        return ["true"]
    if action == "ensure-disable-cache":
        conf_raw = _parse_flag(rest, "conf")
        if not conf_raw:
            raise ValueError("usage: ensure-disable-cache --conf=PATH")
        conf = _validate_conf_path(conf_raw)
        _ensure_disable_cache(conf)
        restart_clam_stack(
            _parse_flag(rest, "clamd-unit"),
            _parse_flag(rest, "clamonacc-unit"),
            sockets=sockets,
        )
        return ["true"]
    if action == "restart-stack":
        restart_clam_stack(
            _parse_flag(rest, "clamd-unit"),
            _parse_flag(rest, "clamonacc-unit"),
            sockets=sockets,
        )
        return ["true"]
    raise ValueError(f"unknown clamd-cocontrol action: {action}")


__all__ = [
    "DENIED_INCLUDE_PREFIXES",
    "FDPASS_DROPIN_NAME",
    "HARDEN_BEGIN",
    "HARDEN_END",
    "ONACCESS_BEGIN",
    "ONACCESS_END",
    "VIRUSEVENT_BEGIN",
    "VIRUSEVENT_END",
    "_build_clamd_cocontrol_argv",
    "_replace_marked_block",
]
