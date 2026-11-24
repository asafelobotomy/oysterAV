"""``oyst-cli firewall overview|turn|use|policy|rule|zone``: what uQ Settings' Firewall tab runs.

Every value is a positional argument (uQ appends arguments, never options). Each change takes
``--dry-run --json`` and prints one plan document for the confirmation sheet, and ``--confirm`` to
change something. The work is in ``oyst_core.packs.firewall_page``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit

STATE = click.Choice(["on", "off"])
BACKEND = click.Choice(["ufw", "firewalld"])
DIRECTION = click.Choice(["incoming", "outgoing", "routed"])
POLICY = click.Choice(["allow", "deny", "reject"])
ACTION = click.Choice(["allow", "deny", "limit"])
PROTO = click.Choice(["tcp", "udp"])
OP = click.Choice(["add", "remove"])


def _finish(
    run: Callable[..., dict[str, Any]], *, confirm: bool, dry_run: bool, json_mode: bool
) -> None:
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to change the firewall")
    if dry_run:
        doc = run(dry_run=True)
        if json_mode:
            emit({"ok": True, "dry_run": True, **doc}, json_mode=True)
        else:
            click.echo(doc["reason"] if doc.get("would_refuse") else doc["summary"])
        return
    result = run(dry_run=False)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


def _change_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    fn = click.option("--json", "json_mode", is_flag=True)(fn)
    fn = click.option("--dry-run", is_flag=True, help="Print the plan; change nothing")(fn)
    return click.option("--confirm", is_flag=True)(fn)


def register_page_commands(firewall_group: click.Group) -> None:
    from oyst_core.packs import firewall_page as fp

    @firewall_group.command("overview")
    @click.option("--json", "json_mode", is_flag=True)
    def firewall_overview_cmd(json_mode: bool) -> None:
        """Firewall state, default rules, rules and zones in one read (no password)."""
        from oyst_core.packs.firewall_view import firewall_overview

        emit(firewall_overview(), json_mode=json_mode)

    @firewall_group.command("turn")
    @click.argument("state", type=STATE)
    @_change_options
    def firewall_turn(state: str, confirm: bool, dry_run: bool, json_mode: bool) -> None:
        """Turn the firewall (UFW or firewalld) on or off."""
        _finish(
            lambda **kw: fp.power(state, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_group.command("use")
    @click.argument("backend", type=BACKEND)
    @_change_options
    def firewall_use(backend: str, confirm: bool, dry_run: bool, json_mode: bool) -> None:
        """Make UFW or firewalld the firewall (stops the other)."""
        _finish(
            lambda **kw: fp.use(backend, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_group.command("policy")
    @click.argument("direction", type=DIRECTION)
    @click.argument("choice", type=POLICY)
    @_change_options
    def firewall_policy(
        direction: str, choice: str, confirm: bool, dry_run: bool, json_mode: bool
    ) -> None:
        """Set UFW's default for incoming, outgoing or routed connections."""
        _finish(
            lambda **kw: fp.policy(direction, choice, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_group.group("rule")
    def firewall_rule_group() -> None:
        """UFW rules for incoming connections: SOURCE is "anywhere" or an address or network."""

    @firewall_rule_group.command("add")
    @click.argument("action", type=ACTION)
    @click.argument("port")
    @click.argument("proto", type=PROTO)
    @click.argument("source")
    @_change_options
    def rule_add(
        action: str,
        port: str,
        proto: str,
        source: str,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Add a rule: PORT is 8080 or a range 1714:1764."""
        _finish(
            lambda **kw: fp.rule_add(action, port, proto, source, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_rule_group.command("remove")
    @click.argument("action", type=ACTION)
    @click.argument("port")
    @click.argument("proto", type=PROTO)
    @click.argument("source")
    @_change_options
    def rule_remove(
        action: str,
        port: str,
        proto: str,
        source: str,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Remove a rule, named as it was added."""
        _finish(
            lambda **kw: fp.rule_remove(action, port, proto, source, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_rule_group.command("change")
    @click.argument("old_action", type=ACTION)
    @click.argument("old_port")
    @click.argument("old_proto", type=PROTO)
    @click.argument("old_source")
    @click.argument("new_action", type=ACTION)
    @click.argument("new_port")
    @click.argument("new_proto", type=PROTO)
    @click.argument("new_source")
    @_change_options
    def rule_change(
        old_action: str,
        old_port: str,
        old_proto: str,
        old_source: str,
        new_action: str,
        new_port: str,
        new_proto: str,
        new_source: str,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Replace one rule with another, with one password prompt."""
        old = [old_action, old_port, old_proto, old_source]
        new = [new_action, new_port, new_proto, new_source]
        _finish(
            lambda **kw: fp.rule_change(old, new, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_group.group("zone")
    def firewall_zone_group() -> None:
        """firewalld: open or close ports and services in a zone."""

    @firewall_zone_group.command("port")
    @click.argument("op", type=OP)
    @click.argument("zone")
    @click.argument("spec")
    @_change_options
    def zone_port(
        op: str, zone: str, spec: str, confirm: bool, dry_run: bool, json_mode: bool
    ) -> None:
        """Open or close a port (8080/tcp) in ZONE."""
        _finish(
            lambda **kw: fp.zone_open("port", op, zone, spec, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )

    @firewall_zone_group.command("service")
    @click.argument("op", type=OP)
    @click.argument("zone")
    @click.argument("service")
    @_change_options
    def zone_service(
        op: str, zone: str, service: str, confirm: bool, dry_run: bool, json_mode: bool
    ) -> None:
        """Open or close a service (ssh, http) in ZONE."""
        _finish(
            lambda **kw: fp.zone_open("service", op, zone, service, **kw),
            confirm=confirm,
            dry_run=dry_run,
            json_mode=json_mode,
        )
