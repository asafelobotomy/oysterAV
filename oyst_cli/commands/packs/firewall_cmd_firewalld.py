"""firewalld subcommands for oyst-cli firewall."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.firewall_ops import FirewallOps


def register_firewalld_commands(firewall_group: click.Group) -> None:
    @firewall_group.group("firewalld")
    def firewall_firewalld_group() -> None:
        """firewalld rule management (when firewalld is active)."""

    @firewall_firewalld_group.command("add-port")
    @click.argument("port_spec")
    @click.option("--zone", default="public", show_default=True)
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_add_port(
        port_spec: str,
        zone: str,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Add permanent port (e.g. 443/tcp)."""
        require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
        result = FirewallOps().firewalld_port("add-port", port_spec, zone=zone, dry_run=dry_run)
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("remove-port")
    @click.argument("port_spec")
    @click.option("--zone", default="public", show_default=True)
    @click.option("--force-lockout-risk", is_flag=True)
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_remove_port(
        port_spec: str,
        zone: str,
        force_lockout_risk: bool,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Remove permanent port."""
        require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
        result = FirewallOps().firewalld_port(
            "remove-port",
            port_spec,
            zone=zone,
            dry_run=dry_run,
            force_lockout=force_lockout_risk,
        )
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("add-service")
    @click.argument("service")
    @click.option("--zone", default="public", show_default=True)
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_add_service(
        service: str,
        zone: str,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Add permanent service (e.g. ssh)."""
        require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
        result = FirewallOps().firewalld_service("add-service", service, zone=zone, dry_run=dry_run)
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("remove-service")
    @click.argument("service")
    @click.option("--zone", default="public", show_default=True)
    @click.option("--force-lockout-risk", is_flag=True)
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_remove_service(
        service: str,
        zone: str,
        force_lockout_risk: bool,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Remove permanent service."""
        require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
        result = FirewallOps().firewalld_service(
            "remove-service",
            service,
            zone=zone,
            dry_run=dry_run,
            force_lockout=force_lockout_risk,
        )
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("rich-rule")
    @click.argument("action", type=click.Choice(["add", "remove"]))
    @click.argument("rule")
    @click.option("--zone", default="public", show_default=True)
    @click.option("--force-lockout-risk", is_flag=True)
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_rich_rule(
        action: str,
        rule: str,
        zone: str,
        force_lockout_risk: bool,
        confirm: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Add or remove a rich rule."""
        require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
        fw_action = "add-rich-rule" if action == "add" else "remove-rich-rule"
        result = FirewallOps().firewalld_rich_rule(
            fw_action,
            rule,
            zone=zone,
            dry_run=dry_run,
            force_lockout=force_lockout_risk,
        )
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("disable")
    @click.option("--confirm", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_disable(confirm: bool, dry_run: bool, json_mode: bool) -> None:
        """Stop firewalld (managed Off; does not wipe zones)."""
        require_confirm(
            confirm,
            dry_run=dry_run,
            message="--confirm required to disable firewalld",
        )
        result = FirewallOps().firewalld_lifecycle("disable", dry_run=dry_run)
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_firewalld_group.command("reload")
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewalld_reload(dry_run: bool, json_mode: bool) -> None:
        """Reload firewalld."""
        result = FirewallOps().firewalld_reload(dry_run=dry_run)
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)
