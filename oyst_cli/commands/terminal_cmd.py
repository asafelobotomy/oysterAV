"""Session transcript (Settings Terminal) commands."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core import terminal_log


@click.group("terminal")
def terminal_group() -> None:
    """Verbose session transcript (structured + raw backend log)."""


@terminal_group.command("list")
@click.option("--limit", default=200, type=int, show_default=True)
@click.option("--since-id", default=0, type=int, show_default=True)
@click.option(
    "--raw",
    "include_raw",
    is_flag=True,
    help="Include raw layer lines (default: structured only).",
)
@click.option(
    "--all-layers",
    is_flag=True,
    help="Include structured and raw layers.",
)
@click.option("--json", "json_mode", is_flag=True)
def terminal_list_cmd(
    limit: int,
    since_id: int,
    include_raw: bool,
    all_layers: bool,
    json_mode: bool,
) -> None:
    """List recent transcript entries (oldest→newest)."""
    if all_layers:
        layers = None
    elif include_raw:
        layers = ["structured", "raw"]
    else:
        layers = ["structured"]
    rows = terminal_log.list_entries(limit=limit, since_id=since_id, layers=layers)
    if json_mode:
        emit(rows, json_mode=True)
        return
    if not rows:
        click.echo("No transcript entries.")
        return
    for row in rows:
        click.echo(terminal_log.format_entry_txt(row))


@terminal_group.command("clear")
@click.option("--confirm", is_flag=True, required=True, help="Required to clear the log.")
@click.option("--json", "json_mode", is_flag=True)
def terminal_clear_cmd(confirm: bool, json_mode: bool) -> None:
    """Clear the persistent session transcript."""
    if not confirm:
        raise click.UsageError("Refusing to clear without --confirm")
    result = terminal_log.clear()
    if json_mode:
        emit(result, json_mode=True)
        return
    click.echo("Terminal log cleared.")


@terminal_group.command("export")
@click.option("-o", "--output", "path", required=True, type=click.Path())
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["txt", "jsonl"], case_sensitive=False),
    default="txt",
    show_default=True,
)
@click.option("--json", "json_mode", is_flag=True)
def terminal_export_cmd(path: str, fmt: str, json_mode: bool) -> None:
    """Export the transcript under ~/.local/share/oysterav/exports/."""
    result = terminal_log.export(path, fmt=fmt)
    if json_mode:
        emit(result, json_mode=True)
        return
    if not result.get("ok"):
        click.echo(f"Export failed: {result.get('error')}", err=True)
        raise SystemExit(1)
    click.echo(f"Exported {result.get('count', 0)} entries to {result.get('path')}")
