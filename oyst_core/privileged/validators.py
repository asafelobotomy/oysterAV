"""Input validators for privileged helper subcommands."""

from __future__ import annotations

import ipaddress
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


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def validate_cidr(value: str) -> str:
    network = ipaddress.ip_network(value.strip(), strict=False)
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


def validate_monitor_mode(value: str) -> str:
    cleaned = value.strip()
    if cleaned == "users":
        return cleaned
    if cleaned.startswith("/"):
        for part in cleaned.split(","):
            part = part.strip()
            if not part:
                continue
            if any(ch in part for ch in ('"', "\n", "\r", ";", "|", "&", "$", "`", "\\")):
                raise ValueError(f"monitor path contains disallowed characters: {part}")
            path = Path(part)
            if not path.is_absolute():
                raise ValueError(f"monitor path must be absolute: {part}")
            if ".." in path.parts:
                raise ValueError(f"monitor path must not contain '..': {part}")
        return cleaned
    raise ValueError("monitor mode must be 'users' or comma-separated absolute paths")


def validate_rich_rule(rule: str) -> str:
    """Allow a small firewalld rich-rule subset (no shell metacharacters)."""
    cleaned = rule.strip()
    if not cleaned or len(cleaned) > 512:
        raise ValueError("rich rule empty or too long")
    if any(ch in cleaned for ch in (";", "|", "&", "$", "`", "(", ")", '"', "'", "\n", "\r", "\0")):
        raise ValueError("rich rule contains disallowed characters")
    # rule [family=ipv4|ipv6] [source address=IP/CIDR]
    #   (port port=N protocol=tcp|udp | service name=NAME) accept|reject|drop
    pattern = re.compile(
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
    match = pattern.fullmatch(cleaned)
    if not match:
        raise ValueError(
            "rich rule must match: rule [family=…] [source address=…] "
            "(port port=N protocol=tcp|udp | service name=NAME) accept|reject|drop",
        )
    port = match.group(3)
    if port is not None:
        validate_port(port)
    src = match.group(2)
    if src is not None:
        if "/" in src:
            validate_cidr(src)
        else:
            validate_ip(src)
    return cleaned


def rich_rule_ssh_lockout_risk(rule: str) -> bool:
    """True when a validated rich rule would drop/reject SSH (service or port 22)."""
    cleaned = validate_rich_rule(rule)
    lowered = cleaned.lower()
    if not lowered.endswith((" drop", " reject")):
        return False
    if "service name=ssh" in lowered:
        return True
    return "port port=22 " in lowered
