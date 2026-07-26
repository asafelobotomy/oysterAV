"""Firewall detection and rule management CLI commands."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.commands.packs.firewall_cmd_firewalld import register_firewalld_commands
from oyst_cli.commands.packs.firewall_cmd_manage import register_manage_commands
from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.firewall_ops import FirewallOps


@click.group("firewall")
def firewall_group() -> None:
    """Firewall detection, status, and rule management."""


register_manage_commands(firewall_group)
register_firewalld_commands(firewall_group)


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
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_deny(
    port: str | None,
    proto: str,
    from_addr: str | None,
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Add UFW deny rule."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "deny",
        port=port,
        proto=proto,
        from_addr=from_addr,
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
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
@click.option(
    "--rule-action",
    type=click.Choice(["allow", "deny", "limit", "reject"]),
    default="allow",
    show_default=True,
    help="Original rule verb (ufw requires: delete allow 123/tcp)",
)
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_delete(
    port: str | None,
    proto: str,
    rule_action: str,
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Delete UFW rule (emits ``ufw delete <rule-action> PORT/PROTO``)."""
    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    result = FirewallOps().ufw_rule(
        "delete",
        port=port,
        proto=proto,
        rule_action=rule_action,
        dry_run=dry_run,
        force_lockout=force_lockout_risk,
    )
    emit(result.__dict__, json_mode=json_mode)
    raise SystemExit(0 if result.ok else 2)


@firewall_ufw_group.command("batch")
@click.option(
    "--rule",
    "rules",
    multiple=True,
    help='JSON rule object, e.g. \'{"action":"allow","port":"443","proto":"tcp"}\'',
)
@click.option("--confirm", is_flag=True)
@click.option("--force-lockout-risk", is_flag=True)
@click.option("--dry-run", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def firewall_ufw_batch(
    rules: tuple[str, ...],
    confirm: bool,
    force_lockout_risk: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Apply many UFW rules with one authentication."""
    import json

    from oyst_core.packs.firewall_batch import ufw_batch

    require_confirm(confirm, dry_run=dry_run, message="--confirm required to mutate UFW rules")
    if not rules:
        raise click.UsageError("at least one --rule=… is required")
    parsed: list[dict[str, object]] = []
    for raw in rules:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise click.UsageError(f"invalid --rule JSON: {exc}") from exc
        if not isinstance(item, dict):
            raise click.UsageError("each --rule must be a JSON object")
        parsed.append(item)
    result = ufw_batch(
        parsed,
        force_lockout=force_lockout_risk,
        dry_run=dry_run,
    )
    emit(result, json_mode=json_mode)
    raise SystemExit(0 if result.get("ok") else 2)


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


@firewall_ufw_group.command("enable")
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
