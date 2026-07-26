"""Read UFW user rules without root (``ufw status`` often needs privileges)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_UFW_USER_RULES = Path("/etc/ufw/user.rules")
_UFW_USER6_RULES = Path("/etc/ufw/user6.rules")

_STATUS_LINE_RE = re.compile(
    r"^(?:\[\s*\d+\]\s+)?"
    r"(?P<port_proto>\S+)\s+"
    r"(?P<action>ALLOW|DENY|REJECT|LIMIT)\s+"
    r"(?P<direction>IN|OUT)\s+"
    r"(?P<rest>.+?)\s*$",
    re.IGNORECASE,
)
_LOOSE_LINE_RE = re.compile(
    r"^(?P<pp>\S+)\s+(?P<act>ALLOW|DENY|REJECT|LIMIT)\s+"
    r"(?P<dir>IN|OUT)\s+(?P<rest>.+)$",
    re.IGNORECASE,
)


def _entry(
    *,
    port: str,
    proto: str,
    action: str,
    direction: str,
    from_addr: str | None,
    ipv6: bool,
) -> dict[str, Any]:
    port_proto = f"{port}/{proto}" if port != "any" else proto
    bits = [direction.upper(), "Anywhere"]
    if from_addr:
        bits.append(f"from {from_addr}")
    if ipv6:
        bits.append("IPv6")
    return {
        "port": port,
        "proto": proto,
        "action": action.lower(),
        "direction": direction.lower(),
        "from_addr": from_addr,
        "ipv6": ipv6,
        "title": f"{port_proto} · {action.upper()}",
        "subtitle": " · ".join(bits),
        "removable": port.isdigit() and action.lower() in {"allow", "deny", "limit", "reject"},
    }


def _format_tuple_line(raw: str, *, ipv6: bool) -> str:
    """Turn ``### tuple ### …`` into a status-like one-liner."""
    parts = raw.removeprefix("### tuple ###").split()
    if len(parts) < 7:
        return raw.strip()
    action, proto, dport, daddr, _sport, saddr, direction = parts[:7]
    port_proto = f"{dport}/{proto}" if dport != "any" else str(proto)
    dest = "Anywhere" if daddr in {"0.0.0.0/0", "::/0", "any"} else daddr
    src = ""
    if saddr not in {"0.0.0.0/0", "::/0", "any"}:
        src = f" from {saddr}"
    suffix = " (v6)" if ipv6 else ""
    return f"{port_proto:22} {action.upper():8} {direction.upper()} {dest}{src}{suffix}"


def _entry_from_tuple_parts(parts: list[str], *, ipv6: bool) -> dict[str, Any]:
    action, proto, dport, _daddr, _sport, saddr, direction = parts[:7]
    from_addr = None if saddr in {"0.0.0.0/0", "::/0", "any"} else saddr
    direction = "in" if direction.lower().startswith("in") else "out"
    return _entry(
        port=dport,
        proto=proto.lower(),
        action=action.lower(),
        direction=direction,
        from_addr=from_addr,
        ipv6=ipv6,
    )


def _tuples_from(path: Path, *, ipv6: bool) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith("### tuple ###"):
            out.append(_format_tuple_line(line, ipv6=ipv6))
    return out


def _entries_from(path: Path, *, ipv6: bool) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.startswith("### tuple ###"):
            continue
        parts = line.removeprefix("### tuple ###").split()
        if len(parts) >= 7:
            out.append(_entry_from_tuple_parts(parts, ipv6=ipv6))
    return out


def ufw_rule_entries_from_files(
    user4: Path = _UFW_USER_RULES,
    user6: Path = _UFW_USER6_RULES,
) -> list[dict[str, Any]]:
    """Structured UFW rules from world-readable user*.rules files."""
    return merge_ufw_entries(_entries_from(user4, ipv6=False) + _entries_from(user6, ipv6=True))


def parse_ufw_status_entries(text: str) -> list[dict[str, Any]]:
    """Parse ``ufw status`` / numbered / file-fallback lines into entries."""
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("status:"):
            continue
        if set(stripped) <= {"-", " "}:
            continue
        match = _STATUS_LINE_RE.match(stripped) or _LOOSE_LINE_RE.match(stripped)
        if not match:
            continue
        groups = match.groupdict()
        port_proto = groups.get("port_proto") or groups.get("pp") or ""
        action = groups.get("action") or groups.get("act") or ""
        direction = groups.get("direction") or groups.get("dir") or ""
        rest = groups.get("rest") or ""
        ipv6 = "(v6)" in rest.lower()
        from_addr = None
        if " from " in rest.lower():
            from_addr = rest.split(" from ", 1)[-1].replace("(v6)", "").strip() or None
        if "/" in port_proto:
            port, proto = port_proto.split("/", 1)
        else:
            port, proto = port_proto, "tcp"
        entries.append(
            _entry(
                port=port,
                proto=proto.lower(),
                action=action.lower(),
                direction=direction.lower(),
                from_addr=from_addr,
                ipv6=ipv6,
            ),
        )
    return merge_ufw_entries(entries)


def merge_ufw_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse matching IPv4+IPv6 pairs into one row for the Shield list."""
    order: list[tuple[str, str, str, str, str | None]] = []
    by_key: dict[tuple[str, str, str, str, str | None], dict[str, Any]] = {}
    for entry in entries:
        key = (
            str(entry.get("port") or ""),
            str(entry.get("proto") or ""),
            str(entry.get("action") or ""),
            str(entry.get("direction") or ""),
            entry.get("from_addr") if isinstance(entry.get("from_addr"), str) else None,
        )
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = dict(entry)
            order.append(key)
            continue
        if bool(entry.get("ipv6")) != bool(existing.get("ipv6")):
            bits = [str(existing.get("direction") or "").upper(), "Anywhere"]
            if existing.get("from_addr"):
                bits.append(f"from {existing['from_addr']}")
            bits.append("IPv4+IPv6")
            existing["subtitle"] = " · ".join(bits)
            existing["ipv6"] = False
    return [by_key[k] for k in order]


def ufw_rules_text_from_files(
    user4: Path = _UFW_USER_RULES,
    user6: Path = _UFW_USER6_RULES,
) -> str:
    """Human-readable rules from world-readable UFW user rule files."""
    lines = _tuples_from(user4, ipv6=False) + _tuples_from(user6, ipv6=True)
    if not lines:
        return ""
    note = "Status: active (from /etc/ufw/user*.rules)"
    return "\n".join([note, *lines])


def ufw_status_or_files(run_command: object, argv: list[str]) -> str:
    """Prefer live ``ufw status``; fall back to user*.rules when status needs root."""
    try:
        res = run_command(argv, timeout=30)  # type: ignore[operator]
        text = (getattr(res, "stdout", None) or "").strip()
        if int(getattr(res, "returncode", 1) or 0) == 0 and text:
            return text
    except (ValueError, OSError, TypeError):
        pass
    return ufw_rules_text_from_files()


__all__ = [
    "merge_ufw_entries",
    "parse_ufw_status_entries",
    "ufw_rule_entries_from_files",
    "ufw_rules_text_from_files",
    "ufw_status_or_files",
]
