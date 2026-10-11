"""Input validators for privileged helper subcommands."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

from oyst_core.privileged.auth_grant_scope import (
    PASSWORDLESS_SYSTEMCTL_ACTIONS,
    PASSWORDLESS_SYSTEMCTL_UNITS,
)

JAIL_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
ZONE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
UNIT_NAME_RE = re.compile(r"^[a-zA-Z0-9@._-]+$")
SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
PROTO_RE = re.compile(r"^(tcp|udp)$")

ALLOWED_SYSTEMCTL_UNITS = frozenset(
    {
        "clamav-daemon",
        "clamd@scan",
        "maldet",
        "fail2ban",
        "clamav-freshclam.timer",
        "clamav-freshclam-once.timer",
        "clamav-freshclam",
        "clamav-clamonacc",
        "firewalld",
    },
)

ALLOWED_SYSTEMCTL_ACTIONS = frozenset(
    {"enable", "disable", "start", "stop", "restart", "enable-now", "disable-now"},
)

UFW_RULE_ACTIONS = frozenset({"allow", "deny", "limit", "delete"})
UFW_DELETE_VERBS = frozenset({"allow", "deny", "limit", "reject"})
UFW_DEFAULT_DIRS = frozenset({"incoming", "outgoing", "routed"})
UFW_DEFAULT_POLICIES = frozenset({"allow", "deny", "reject"})
UFW_LIFECYCLE = frozenset({"enable", "disable", "reload"})

FIREWALLD_PORT_ACTIONS = frozenset({"add-port", "remove-port"})
FIREWALLD_SERVICE_ACTIONS = frozenset({"add-service", "remove-service"})
FIREWALLD_RICH_ACTIONS = frozenset({"add-rich-rule", "remove-rich-rule"})


# Plain IPv4/IPv6 literal characters only. ``ipaddress`` accepts IPv6 scope IDs
# (``fe80::1%<anything>``, including newlines) and echoes them back via str(),
# which would let callers inject lines into root-written config files.
_IP_CHARS_RE = re.compile(r"^[0-9A-Fa-f:.]+$")
_CIDR_CHARS_RE = re.compile(r"^[0-9A-Fa-f:.]+/[0-9]{1,3}$")


def validate_ip(value: str) -> str:
    cleaned = value.strip()
    if not _IP_CHARS_RE.fullmatch(cleaned):
        raise ValueError(f"invalid IP address: {value!r}")
    addr = ipaddress.ip_address(cleaned)
    if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id:
        raise ValueError("IPv6 scope IDs are not supported")
    return str(addr)


def validate_cidr(value: str) -> str:
    cleaned = value.strip()
    if not _CIDR_CHARS_RE.fullmatch(cleaned):
        raise ValueError(f"invalid CIDR: {value!r}")
    network = ipaddress.ip_network(cleaned, strict=False)
    return str(network)


def validate_port(value: str) -> str:
    cleaned = value.strip()
    if not cleaned.isdigit():
        raise ValueError(f"port must be an integer 1-65535, got {value!r}")
    port = int(cleaned)
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")
    return str(port)


def validate_jail(name: str) -> str:
    cleaned = name.strip()
    if not JAIL_NAME_RE.match(cleaned):
        raise ValueError(f"invalid jail name: {name}")
    return cleaned


def validate_zone(name: str) -> str:
    cleaned = name.strip()
    if not ZONE_NAME_RE.match(cleaned):
        raise ValueError(f"invalid zone name: {name}")
    return cleaned


def validate_unit(name: str) -> str:
    cleaned = name.strip()
    if not UNIT_NAME_RE.match(cleaned):
        raise ValueError(f"invalid unit name: {name}")
    if cleaned not in ALLOWED_SYSTEMCTL_UNITS:
        raise ValueError(f"unit not allowlisted: {name}")
    return cleaned


def validate_systemctl_action(action: str) -> str:
    cleaned = action.strip()
    if cleaned not in ALLOWED_SYSTEMCTL_ACTIONS:
        raise ValueError(f"systemctl action not allowlisted: {action}")
    return cleaned


def validate_passwordless_unit(name: str) -> str:
    cleaned = validate_unit(name)
    if cleaned not in PASSWORDLESS_SYSTEMCTL_UNITS:
        raise ValueError(f"unit not allowed for systemctl-up: {name}")
    return cleaned


def validate_passwordless_systemctl_action(action: str) -> str:
    cleaned = validate_systemctl_action(action)
    if cleaned not in PASSWORDLESS_SYSTEMCTL_ACTIONS:
        raise ValueError(f"action not allowed for systemctl-up: {action}")
    return cleaned


def validate_proto(value: str) -> str:
    cleaned = value.strip().lower()
    if not PROTO_RE.match(cleaned):
        raise ValueError(f"invalid protocol: {value}")
    return cleaned


def validate_service_name(value: str) -> str:
    cleaned = value.strip()
    if not SERVICE_NAME_RE.match(cleaned):
        raise ValueError(f"invalid service name: {value}")
    return cleaned


def validate_port_spec(value: str) -> str:
    """Validate firewalld port spec like 443/tcp."""
    if "/" in value:
        port_part, proto = value.split("/", 1)
        return f"{validate_port(port_part)}/{validate_proto(proto)}"
    return validate_port(value)


# maldet interpolates monitor paths into bash; allow only plain path characters.
_MONITOR_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]*$")
# Top-level system dirs (and pseudo-filesystems) never valid as monitor roots.
_MONITOR_DENY_EXACT = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/nix",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/snap",
        "/sys",
        "/usr",
        "/var",
    },
)
_MONITOR_DENY_TREES = ("/proc", "/sys", "/dev", "/run", "/boot")


def _monitor_path_denied(path: str) -> bool:
    norm = os.path.normpath(path)
    if norm in _MONITOR_DENY_EXACT:
        return True
    return any(norm == t or norm.startswith(t + "/") for t in _MONITOR_DENY_TREES)


def validate_monitor_mode(value: str) -> str:
    cleaned = value.strip()
    if cleaned == "users":
        return cleaned
    if cleaned.startswith("/"):
        for part in cleaned.split(","):
            part = part.strip()
            if not part:
                continue
            if not _MONITOR_PATH_RE.fullmatch(part):
                raise ValueError(f"monitor path contains disallowed characters: {part!r}")
            path = Path(part)
            if ".." in path.parts:
                raise ValueError(f"monitor path must not contain '..': {part}")
            resolved = os.path.realpath(part)
            if _monitor_path_denied(part) or _monitor_path_denied(resolved):
                raise ValueError(f"monitor path is a protected system directory: {part}")
            if not os.path.isdir(resolved):
                raise ValueError(f"monitor path must be an existing directory: {part}")
        return cleaned
    raise ValueError("monitor mode must be 'users' or comma-separated absolute paths")


_RICH_RULE_RE = re.compile(
    r"^rule"
    r"(?:\s+family=(ipv4|ipv6))?"
    r"(?:\s+source\s+address=([0-9a-fA-F:.]+(?:/\d{1,3})?))?"
    r"(?:"
    r"(?:\s+port\s+port=(\d{1,5})\s+protocol=(tcp|udp))"
    r"|"
    r"(?:\s+service\s+name=([a-zA-Z0-9][a-zA-Z0-9._-]{0,63}))"
    r")"
    r"\s+(accept|reject|drop)$",
    re.IGNORECASE,
)


def _rich_rule_port_bounds(port: str) -> tuple[int, int]:
    """Return ``(low, high)`` for a rich-rule ``port=N`` or ``port=N-M`` value."""
    low_s, _, high_s = port.partition("-")
    low = int(validate_port(low_s))
    high = int(validate_port(high_s)) if high_s else low
    if high < low:
        raise ValueError(f"rich rule port range is reversed: {port}")
    return low, high


def _match_rich_rule(rule: str) -> re.Match[str]:
    cleaned = rule.strip()
    if not cleaned or len(cleaned) > 512:
        raise ValueError("rich rule empty or too long")
    if any(ch in cleaned for ch in (";", "|", "&", "$", "`", "(", ")", '"', "'", "\n", "\r", "\0")):
        raise ValueError("rich rule contains disallowed characters")
    # rule [family=ipv4|ipv6] [source address=IP/CIDR]
    #   (port port=N protocol=tcp|udp | service name=NAME) accept|reject|drop
    match = _RICH_RULE_RE.fullmatch(cleaned)
    if not match:
        raise ValueError(
            "rich rule must match: rule [family=…] [source address=…] "
            "(port port=N protocol=tcp|udp | service name=NAME) accept|reject|drop",
        )
    port = match.group(3)
    if port is not None:
        _rich_rule_port_bounds(port)
    src = match.group(2)
    if src is not None:
        if "/" in src:
            validate_cidr(src)
        else:
            validate_ip(src)
    return match


def validate_rich_rule(rule: str) -> str:
    """Allow a small firewalld rich-rule subset (no shell metacharacters)."""
    return _match_rich_rule(rule).group(0)


def rich_rule_ssh_lockout_risk(rule: str) -> bool:
    """True when a validated rich rule would drop/reject SSH (service or port 22).

    Uses the parsed port value (``int``), so ``port=022`` and tab separators
    are detected; a ``N-M`` range covering 22 would be too (the grammar
    currently rejects ranges outright).
    """
    match = _match_rich_rule(rule)
    if match.group(6).lower() not in ("drop", "reject"):
        return False
    service = match.group(5)
    if service is not None:
        return service.lower() == "ssh"
    low, high = _rich_rule_port_bounds(match.group(3))
    return low <= 22 <= high
