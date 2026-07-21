"""UFW / firewalld argv builders for oyst-helper."""

from __future__ import annotations

from collections.abc import Sequence

from oyst_core.privileged.validators import (
    FIREWALLD_PORT_ACTIONS,
    FIREWALLD_RICH_ACTIONS,
    FIREWALLD_SERVICE_ACTIONS,
    UFW_DEFAULT_DIRS,
    UFW_DEFAULT_POLICIES,
    UFW_LIFECYCLE,
    UFW_RULE_ACTIONS,
    validate_cidr,
    validate_ip,
    validate_port,
    validate_port_spec,
    validate_proto,
    validate_rich_rule,
    validate_service_name,
    validate_zone,
)


def _parse_flag(argv: Sequence[str], flag: str) -> tuple[str | None, list[str]]:
    rest = list(argv)
    value: str | None = None
    if flag in rest:
        idx = rest.index(flag)
        if idx + 1 >= len(rest):
            raise ValueError(f"missing value for {flag}")
        value = rest[idx + 1]
        del rest[idx : idx + 2]
    return value, rest


def _has_flag(argv: Sequence[str], flag: str) -> bool:
    return flag in argv


def _build_ufw_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("ufw subcommand required")
    action = argv[0]
    rest = list(argv[1:])
    if action in UFW_RULE_ACTIONS:
        port, rest = _parse_flag(rest, "--port")
        proto, rest = _parse_flag(rest, "--proto")
        from_addr, rest = _parse_flag(rest, "--from")
        to_port, rest = _parse_flag(rest, "--to-port")
        if rest:
            raise ValueError(f"unexpected ufw args: {' '.join(rest)}")
        cmd = ["ufw", action]
        port_val = port or to_port
        if from_addr:
            # Full syntax: proto must precede "to" (ufw rejects "... port 22 tcp").
            src = validate_cidr(from_addr) if "/" in from_addr else validate_ip(from_addr)
            cmd.extend(["from", src])
            if proto:
                cmd.extend(["proto", validate_proto(proto)])
            if port_val:
                cmd.extend(["to", "any", "port", validate_port(port_val)])
            return cmd
        if port_val:
            # Simple syntax: "22/tcp" — accepted by all ufw versions.
            if proto:
                cmd.append(f"{validate_port(port_val)}/{validate_proto(proto)}")
            else:
                cmd.append(validate_port(port_val))
            return cmd
        raise ValueError("ufw rule requires --port or --to-port")
    if action == "default":
        if len(rest) < 2:
            raise ValueError("usage: ufw default <incoming|outgoing|routed> <allow|deny|reject>")
        direction = rest[0]
        policy = rest[1]
        if direction not in UFW_DEFAULT_DIRS:
            raise ValueError(f"invalid default direction: {direction}")
        if policy not in UFW_DEFAULT_POLICIES:
            raise ValueError(f"invalid default policy: {policy}")
        return ["ufw", "default", direction, policy]
    if action in UFW_LIFECYCLE:
        if rest:
            raise ValueError(f"unexpected ufw args: {' '.join(rest)}")
        if action == "reload":
            return ["ufw", "reload"]
        return ["ufw", action]
    raise ValueError(f"unknown ufw action: {action}")


def _build_firewalld_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("firewalld subcommand required")
    action = argv[0]
    rest = list(argv[1:])
    zone, rest = _parse_flag(rest, "--zone")
    zone_name = validate_zone(zone or "public")
    if action in FIREWALLD_PORT_ACTIONS:
        if not rest:
            raise ValueError("port spec required")
        port_spec = validate_port_spec(rest[0])
        fw_action = "add-port" if action == "add-port" else "remove-port"
        return [
            "firewall-cmd",
            f"--{fw_action}={port_spec}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action in FIREWALLD_SERVICE_ACTIONS:
        if not rest:
            raise ValueError("service name required")
        service = validate_service_name(rest[0])
        fw_action = "add-service" if action == "add-service" else "remove-service"
        return [
            "firewall-cmd",
            f"--{fw_action}={service}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action in FIREWALLD_RICH_ACTIONS:
        if not rest:
            raise ValueError("rich rule required")
        rule = validate_rich_rule(" ".join(rest))
        fw_action = "add-rich-rule" if action == "add-rich-rule" else "remove-rich-rule"
        return [
            "firewall-cmd",
            f"--{fw_action}={rule}",
            f"--zone={zone_name}",
            "--permanent",
        ]
    if action == "reload":
        return ["firewall-cmd", "--reload"]
    raise ValueError(f"unknown firewalld action: {action}")


def _build_firewall_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("firewall backend required")
    backend = argv[0]
    if backend == "ufw":
        return _build_ufw_argv(argv[1:])
    if backend == "firewalld":
        built = _build_firewalld_argv(argv[1:])
        if built[-1] == "--permanent":
            return built
        return built
    raise ValueError(f"unknown firewall backend: {backend}")
