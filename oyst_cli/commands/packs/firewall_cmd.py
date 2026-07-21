"""Firewall detection and rule management CLI commands."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.firewall_ops import FirewallOps


@click.group("firewall")
def firewall_group() -> None:
    """Firewall detection, status, and rule management."""


@firewall_group.command("detect")
@click.option("--json", "json_mode", is_flag=True)
def firewall_detect(json_mode: bool) -> None:
    """Detect active firewall backend."""
    emit(FirewallPack().detect(), json_mode=json_mode)


@firewall_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def firewall_status(json_mode: bool) -> None:
    """Firewall backend status."""
    emit(FirewallPack().status(), json_mode=json_mode)


@firewall_group.command("audit")
@click.option("--json", "json_mode", is_flag=True)
def firewall_audit(json_mode: bool) -> None:
    """Read-only recommendations (includes fail2ban probe)."""
    pack = FirewallPack()
    recs = pack.audit()
    f2b = pack.fail2ban_status()
    payload = {"recommendations": recs, "fail2ban": f2b}
    if json_mode:
        emit(payload, json_mode=True)
        return
    for line in recs:
        click.echo(line)
    if f2b.get("installed"):
        click.echo("fail2ban: installed")
    else:
        click.echo("fail2ban: not installed (optional)")


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


@firewall_group.command("export")
@click.option("--json", "json_mode", is_flag=True)
def firewall_export(json_mode: bool) -> None:
    """Export current firewall rules snapshot."""
    emit(FirewallOps().export_rules(), json_mode=json_mode)


@firewall_group.command("rules")
@click.option("--verbose/--no-verbose", default=True, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_rules(verbose: bool, json_mode: bool) -> None:
    """Show detailed firewall rules (numbered UFW or all zones)."""
    ops = FirewallOps()
    text = ops.verbose_status() if verbose else str(ops.export_rules().get("rules", ""))
    if json_mode:
        emit({"rules": text}, json_mode=True)
    else:
        click.echo(text)


@firewall_group.command("plan")
@click.argument("proposed", type=click.Path(dir_okay=False))
@click.option("--json", "json_mode", is_flag=True)
def firewall_plan(proposed: str, json_mode: bool) -> None:
    """Diff proposed rule text against the active firewall snapshot."""
    path = Path(proposed).expanduser()
    if not path.is_file():
        raise click.ClickException(f"file not found: {path}")
    content = path.read_text(encoding="utf-8")
    emit(FirewallOps().plan_diff(content), json_mode=json_mode)


@firewall_group.group("ufw")
def firewall_ufw_group() -> None:
    """UFW rule management (when ufw is the active backend)."""


@firewall_ufw_group.command("allow")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--from", "from_addr", default=None)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_allow(
    port: str | None,
    proto: str,
    from_addr: str | None,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW allow rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "allow", port=port, proto=proto, from_addr=from_addr, dry_run=dry_run
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("deny")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--from", "from_addr", default=None)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_deny(
    port: str | None,
    proto: str,
    from_addr: str | None,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW deny rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "deny", port=port, proto=proto, from_addr=from_addr, dry_run=dry_run
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("limit")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_limit(
    port: str | None,
    proto: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW rate-limit rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule("limit", port=port, proto=proto, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("delete")
@click.option("--port")
@click.option("--proto", default="tcp", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_delete(
    port: str | None,
    proto: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Delete UFW rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule("delete", port=port, proto=proto, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("default")
@click.argument("direction", type=click.Choice(["incoming", "outgoing", "routed"]))
@click.argument("policy", type=click.Choice(["allow", "deny", "reject"]))
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_default(
    direction: str,
    policy: str,
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Set UFW default policy."""
    require_confirm(
        confirm,
        dry_run=dry_run,
        message="--confirm required for default policy changes",
    )
    result = FirewallOps().ufw_default(
        direction,
        policy,
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command(
    "enable",
    epilog="""
Examples:
  oyst-cli firewall ufw enable --dry-run --json
  oyst-cli firewall ufw enable --confirm --json
""",
)
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_enable(
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Enable UFW."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to enable firewall")
    result = FirewallOps().ufw_lifecycle(
        "enable",
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("disable")
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_disable(confirm: bool, dry_run: bool, json_mode: bool) -> None:
    """Disable UFW."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to disable firewall")
    result = FirewallOps().ufw_lifecycle("disable", dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


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
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_remove_port(
    port_spec: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Remove permanent port."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_port("remove-port", port_spec, zone=zone, dry_run=dry_run)
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
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_remove_service(
    service: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Remove permanent service."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    result = FirewallOps().firewalld_service("remove-service", service, zone=zone, dry_run=dry_run)
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_firewalld_group.command("rich-rule")
@click.argument("action", type=click.Choice(["add", "remove"]))
@click.argument("rule")
@click.option("--zone", default="public", show_default=True)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewalld_rich_rule(
    action: str,
    rule: str,
    zone: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add or remove a rich rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate firewalld")
    fw_action = "add-rich-rule" if action == "add" else "remove-rich-rule"
    result = FirewallOps().firewalld_rich_rule(fw_action, rule, zone=zone, dry_run=dry_run)
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
