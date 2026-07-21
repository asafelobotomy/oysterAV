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
    port = int(value)
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
    cleaned = rule.strip()
    if len(cleaned) > 512:
        raise ValueError("rich rule too long")
    if any(ch in cleaned for ch in (";", "|", "&", "$", "`", "(", ")")):
        raise ValueError("rich rule contains disallowed characters")
    lowered = cleaned.lower()
    if not any(token in lowered for token in ("accept", "reject", "drop")):
        raise ValueError("rich rule must include accept, reject, or drop")
    return cleaned
