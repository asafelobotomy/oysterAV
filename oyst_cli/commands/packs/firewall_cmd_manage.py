"""Firewall select / recommend / ensure-enable CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.firewall_ops import FirewallOps
from oyst_core.packs.firewall_select import (
    recommended_managed_backend,
    select_managed_backend,
)


def register_manage_commands(firewall_group: click.Group) -> None:
    @firewall_group.command("select")
    @click.argument("backend", type=click.Choice(["ufw", "firewalld", "none"]))
    @click.option("--confirm", is_flag=True)
    @click.option("--force-lockout-risk", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewall_select(
        backend: str,
        confirm: bool,
        force_lockout_risk: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Soft-swap managed firewall (stops the other; SSH-safe enable)."""
        require_confirm(
            confirm,
            dry_run=dry_run,
            message="--confirm required to select firewall",
        )
        result = select_managed_backend(
            backend,
            force_lockout=force_lockout_risk,
            dry_run=dry_run,
        )
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok else 2)

    @firewall_group.command("recommend")
    @click.option("--json", "json_mode", is_flag=True)
    def firewall_recommend(json_mode: bool) -> None:
        """Recommended managed backend for this distro + current detect."""
        emit(
            {
                "recommended": recommended_managed_backend(),
                "detect": FirewallPack().detect(),
            },
            json_mode=json_mode,
        )

    @firewall_group.command("ensure-enable")
    @click.option("--confirm", is_flag=True)
    @click.option("--force-lockout-risk", is_flag=True)
    @click.option("--dry-run", is_flag=True)
    @click.option("--json", "json_mode", is_flag=True)
    def firewall_ensure_enable(
        confirm: bool,
        force_lockout_risk: bool,
        dry_run: bool,
        json_mode: bool,
    ) -> None:
        """Enable UFW or firewalld when installed but inactive (SSH-safe)."""
        require_confirm(
            confirm,
            dry_run=dry_run,
            message="--confirm required to enable host firewall",
        )
        result = FirewallOps().ensure_firewall_enabled(
            force_lockout=force_lockout_risk,
            dry_run=dry_run,
        )
        emit(result.__dict__, json_mode=json_mode)
        raise SystemExit(0 if result.ok or result.skipped else 2)
