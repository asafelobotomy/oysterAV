"""Security audit log commands."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.audit import SecurityAudit


@click.group("audit")
def audit_group() -> None:
    """Security audit trail for privileged operations."""


@audit_group.command("list")
@click.option("--limit", default=50, type=int, show_default=True)
@click.option("--json", "json_mode", is_flag=True)
def audit_list_cmd(limit: int, json_mode: bool) -> None:
    """List recent security audit entries."""
    rows = SecurityAudit().list_entries(limit=limit)
    if json_mode:
        emit(rows, json_mode=True)
        return
    if not rows:
        click.echo("No audit entries.")
        return
    for row in rows:
        ok = "ok" if row.get("success") else "FAIL"
        click.echo(f"{row.get('ts', '')} [{ok}] {row.get('kind', '')}: {row.get('action', '')}")
