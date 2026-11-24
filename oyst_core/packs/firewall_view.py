"""One read of the host firewall for uQ Settings' Firewall tab (``oyst-cli firewall overview``).

Everything here runs as the user and changes nothing: ``ufw status`` when it answers without root,
else UFW's own files; ``firewall-cmd`` reads (firewalld lets any local user read its state).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.privileged.runner import run_command, which

_UFW_DEFAULTS = Path("/etc/default/ufw")
_UFW_RULES = (Path("/etc/ufw/user.rules"), Path("/etc/ufw/user6.rules"))
_POLICY_WORDS = {"DROP": "deny", "ACCEPT": "allow", "REJECT": "reject"}
_DEFAULT_KEYS = {
    "incoming": "DEFAULT_INPUT_POLICY",
    "outgoing": "DEFAULT_OUTPUT_POLICY",
    "routed": "DEFAULT_FORWARD_POLICY",
}
_SSH_UNITS = ("sshd.service", "ssh.service", "sshd.socket", "ssh.socket")
_ZONE_HEAD_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]{0,63})(?:\s+\((?P<tags>[^)]*)\))?$"
)


def ssh_in_use() -> bool:
    """True when this computer can be reached over SSH (a server is running, or we came in by SSH).

    Only then can a firewall change lock someone out, so only then does oysterAV keep port 22 open.
    """
    if os.environ.get("SSH_CONNECTION"):
        return True
    for unit in _SSH_UNITS:
        try:
            res = run_command(["systemctl", "is-active", unit], timeout=10)
        except (ValueError, OSError):
            continue
        if res.stdout.strip() == "active":
            return True
    return False


def ufw_defaults(path: Path | None = None) -> dict[str, str]:
    """/etc/default/ufw's default policies: {incoming, outgoing, routed} -> allow|deny|reject."""
    try:
        text = (path or _UFW_DEFAULTS).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, raw = line.strip().partition("=")
        if sep and not key.startswith("#"):
            values[key.strip()] = raw.strip().strip("\"'").upper()
    out: dict[str, str] = {}
    for direction, key in _DEFAULT_KEYS.items():
        word = _POLICY_WORDS.get(values.get(key, ""))
        if word:
            out[direction] = word
    return out


def _ufw_entries() -> tuple[list[dict[str, Any]], bool]:
    """The UFW rules and whether they could be read at all."""
    from oyst_core.packs.firewall_ufw_read import (
        parse_ufw_status_entries,
        ufw_rule_entries_from_files,
    )

    try:
        res = run_command(["ufw", "status", "verbose"], timeout=30)
        if res.returncode == 0 and "Status:" in res.stdout:
            return parse_ufw_status_entries(res.stdout), True
    except (ValueError, OSError):
        pass
    readable = any(os.access(p, os.R_OK) for p in _UFW_RULES if p.exists())
    return ufw_rule_entries_from_files(*_UFW_RULES), readable


def _rule_row(entry: dict[str, Any]) -> dict[str, Any]:
    """A rule as the page shows it; `source` is "anywhere" or the address it is limited to."""
    port = str(entry.get("port") or "")
    proto = str(entry.get("proto") or "any")
    removable = bool(entry.get("removable"))
    action = str(entry.get("action") or "")
    return {
        "action": action,
        "port": port,
        "proto": proto,
        "direction": str(entry.get("direction") or "in"),
        "source": str(entry.get("from_addr") or "anywhere"),
        "ipv6_only": bool(entry.get("ipv6")),
        "title": str(entry.get("title") or ""),
        "subtitle": str(entry.get("subtitle") or ""),
        "removable": removable,
        # The page offers only what it can add back: allow, deny or limit.
        "editable": removable and action in {"allow", "deny", "limit"},
    }


def parse_zones(text: str, default_zone: str) -> list[dict[str, Any]]:
    """``firewall-cmd --list-all-zones`` as [{name, default, active, interfaces, services, ...}]."""
    zones: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace():
            match = _ZONE_HEAD_RE.match(raw.strip())
            if not match:
                current = None
                continue
            tags = (match.group("tags") or "").replace(" ", "").split(",")
            current = {
                "name": match.group("name"),
                "default": match.group("name") == default_zone or "default" in tags,
                "active": "active" in tags,
                "target": "default",
                "interfaces": [],
                "sources": [],
                "services": [],
                "ports": [],
            }
            zones.append(current)
            continue
        if current is None:
            continue
        key, sep, value = raw.strip().partition(":")
        if not sep:
            continue
        words = value.split()
        if key in {"interfaces", "sources", "services", "ports"}:
            current[key] = words[:200]
        elif key == "target" and words:
            current["target"] = words[0]
    zones.sort(key=lambda z: (not z["default"], not z["active"], z["name"]))
    return zones


def _firewalld_zones() -> list[dict[str, Any]]:
    try:
        default = run_command(["firewall-cmd", "--get-default-zone"], timeout=15).stdout.strip()
        res = run_command(["firewall-cmd", "--permanent", "--list-all-zones"], timeout=30)
    except (ValueError, OSError):
        return []
    if res.returncode != 0:
        return []
    zones = parse_zones(res.stdout, default)
    try:
        active = run_command(["firewall-cmd", "--get-active-zones"], timeout=15).stdout
    except (ValueError, OSError):
        active = ""
    names = {line.strip() for line in active.splitlines() if line and not line[0].isspace()}
    for zone in zones:
        zone["active"] = zone["active"] or zone["name"] in names
    return zones


def firewall_overview() -> dict[str, Any]:
    """The firewall as uQ Settings shows it. Never asks for a password."""
    from oyst_core.packs.firewall_select import recommended_managed_backend

    invalidate_firewall_detect_cache()
    det = FirewallPack().detect()
    active = str(det.get("active") or "none")
    ufw_installed = bool(det.get("ufw"))
    firewalld_installed = bool(det.get("firewalld"))
    # The program the page manages: the one running, else the one installed (UFW first).
    if active in {"ufw", "firewalld"}:
        backend = active
    elif ufw_installed:
        backend = "ufw"
    elif firewalld_installed:
        backend = "firewalld"
    else:
        backend = "none"
    out: dict[str, Any] = {
        "ok": True,
        "backend": backend,
        "on": active in {"ufw", "firewalld"},
        "active": active,
        "conflict": bool(det.get("conflict")),
        "installed": {"ufw": ufw_installed, "firewalld": firewalld_installed},
        "recommended": recommended_managed_backend(),
        "ssh_in_use": ssh_in_use(),
        "defaults": {},
        "rules": [],
        "rules_readable": True,
        "zones": [],
        "version": str(det.get("version") or ""),
    }
    if backend == "ufw":
        out["defaults"] = ufw_defaults()
        entries, readable = _ufw_entries()
        out["rules"] = [_rule_row(e) for e in entries]
        out["rules_readable"] = readable
    elif backend == "firewalld" and which("firewall-cmd") and active == "firewalld":
        out["zones"] = _firewalld_zones()
    return out


__all__ = ["firewall_overview", "parse_zones", "ssh_in_use", "ufw_defaults"]
