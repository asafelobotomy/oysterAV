"""Status and history commands."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.events import EventLog
from oyst_core.health import assess_health
from oyst_core.orchestrator import JobOrchestrator


@click.group("status", invoke_without_command=True)
@json_option
@click.pass_context
def status_group(ctx: click.Context, json_mode: bool) -> None:
    """Aggregate system security status."""
    ctx.ensure_object(dict)
    ctx.obj["json_mode"] = json_mode
    if ctx.invoked_subcommand is None:
        data = JobOrchestrator().aggregate_status()
        emit(data, json_mode=json_mode)


@status_group.command(
    "assess",
    epilog="""
Examples:
  oyst-cli status assess --json
  oyst-cli status assess
""",
)
@json_option
def status_assess_cmd(json_mode: bool) -> None:
    """Structured health assessment with recommended actions."""
    status = JobOrchestrator().aggregate_status()
    data = assess_health(status)
    if json_mode:
        emit(data, json_mode=True)
        return
    click.echo(f"Severity: {data.get('severity', 'ok')}")
    if data.get("show_banner"):
        click.echo(f"{data.get('banner_title', '')}: {data.get('banner_body', '')}")
    for issue in data.get("issues", []):
        click.echo(f"  [{issue.get('severity', '?')}] {issue.get('title', '')}")
        if issue.get("recommended_action"):
            click.echo(f"    → {issue['recommended_action']}")


@click.group("history", invoke_without_command=True)
@click.option("--limit", default=20, type=int)
@json_option
@click.pass_context
def history_group(ctx: click.Context, limit: int, json_mode: bool) -> None:
    """Show scan history (default: list recent scans)."""
    ctx.ensure_object(dict)
    ctx.obj["json_mode"] = json_mode
    if ctx.invoked_subcommand is None:
        rows = EventLog().history(limit=limit)
        emit(rows, json_mode=json_mode)


@history_group.command("show")
@click.argument("job_id")
@json_option
def history_show_cmd(job_id: str, json_mode: bool) -> None:
    """Show one persisted scan result by job id."""
    result = EventLog().get_scan(job_id)
    if result is None:
        raise click.ClickException(f"scan not found: {job_id}")
    emit(result, json_mode=json_mode)


@history_group.command("handle-open")
@click.argument("job_id")
@click.option("--quarantine", is_flag=True, help="Quarantine open malware findings")
@click.option("--resolve", is_flag=True, help="Resolve open rkhunter advisories")
@click.option("--force", is_flag=True, help="Pass force to rkhunter resolve")
@click.option("--confirm", is_flag=True)
@json_option
def history_handle_open_cmd(
    job_id: str,
    quarantine: bool,
    resolve: bool,
    force: bool,
    confirm: bool,
    json_mode: bool,
) -> None:
    """Quarantine and/or resolve all open actionable findings for a scan."""
    from oyst_cli.confirm import require_confirm
    from oyst_core.history_actions import handle_open_findings

    require_confirm(confirm, message="--confirm required to handle open findings")
    result = handle_open_findings(
        job_id,
        quarantine=quarantine,
        resolve=resolve,
        force=force,
    )
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(
            f"quarantined={result.get('quarantined', 0)} "
            f"resolved={result.get('resolved', 0)} "
            f"errors={len(result.get('errors') or [])}"
        )
        for err in result.get("errors") or []:
            click.echo(f"  {err}", err=True)
    raise SystemExit(0 if result.get("ok") else 2)


@history_group.command("delete")
@click.argument("job_id")
@click.option("--confirm", is_flag=True)
@json_option
def history_delete_cmd(job_id: str, confirm: bool, json_mode: bool) -> None:
    """Delete one scan report from history."""
    from oyst_cli.confirm import require_confirm

    require_confirm(confirm, message="--confirm required to delete a scan report")
    result = EventLog().delete_scan(job_id)
    if json_mode:
        emit(result, json_mode=True)
    else:
        if not result.get("ok"):
            raise click.ClickException(str(result.get("error") or "delete failed"))
        click.echo(f"Deleted report {job_id}")
    raise SystemExit(0 if result.get("ok") else 2)


@history_group.command("delete-all")
@click.option("--confirm", is_flag=True)
@json_option
def history_delete_all_cmd(confirm: bool, json_mode: bool) -> None:
    """Delete every scan report from history."""
    from oyst_cli.confirm import require_confirm

    require_confirm(confirm, message="--confirm required to delete all scan reports")
    result = EventLog().delete_all_scans()
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(f"Deleted {result.get('deleted', 0)} report(s)")
    raise SystemExit(0 if result.get("ok") else 2)


@history_group.command("export")
@click.argument("job_id")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "md"], case_sensitive=False),
    default="json",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(path_type=str),
    help="Output file under ~/.local/share/oysterav/exports/",
)
@json_option
def history_export_cmd(job_id: str, fmt: str, output: str, json_mode: bool) -> None:
    """Export one scan report to JSON or Markdown."""
    from oyst_core.history_export import export_scan_to_path

    result = export_scan_to_path(job_id, output, fmt=fmt)
    if json_mode:
        emit(result, json_mode=True)
    else:
        if not result.get("ok"):
            raise click.ClickException(str(result.get("error") or "export failed"))
        click.echo(f"Wrote {result.get('path')}")
    raise SystemExit(0 if result.get("ok") else 2)


@history_group.command("export-all")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "md"], case_sensitive=False),
    default="json",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    required=True,
    type=click.Path(path_type=str),
    help="Output file under ~/.local/share/oysterav/exports/",
)
@click.option("--limit", default=500, type=int, show_default=True)
@json_option
def history_export_all_cmd(fmt: str, output: str, limit: int, json_mode: bool) -> None:
    """Export all scan reports to one JSON or Markdown file."""
    from oyst_core.history_export import export_all_scans_to_path

    result = export_all_scans_to_path(output, fmt=fmt, limit=limit)
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(f"Wrote {result.get('count', 0)} report(s) to {result.get('path')}")
    raise SystemExit(0 if result.get("ok") else 2)


# Back-compat alias for imports that still expect history_cmd.
history_cmd = history_group
