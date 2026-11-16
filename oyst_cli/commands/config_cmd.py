"""Config commands."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core import config_schema
from oyst_core.config import config_path, get_config_value, load_config, set_config_value
from oyst_core.models import ExitCode
from oyst_core.plan import change, plan_doc, refused


@click.group("config")
def config_group() -> None:
    """Configuration management."""


@config_group.command("path")
@json_option
def config_path_cmd(json_mode: bool) -> None:
    path = str(config_path())
    if json_mode:
        emit({"path": path}, json_mode=True)
    else:
        click.echo(path)


@config_group.command("get")
@click.argument("key", required=False, default=None)
@json_option
def config_get(key: str | None, json_mode: bool) -> None:
    """Get a config value, or dump all config when KEY is omitted."""
    if key is None:
        payload = load_config().model_dump()
        emit(payload, json_mode=json_mode)
        return
    val = get_config_value(key)
    if val is None:
        raise click.ClickException(f"unknown key: {key}")
    if json_mode:
        emit({key: val}, json_mode=True)
    else:
        click.echo(val)


@config_group.command("show")
@json_option
def config_show(json_mode: bool) -> None:
    """Every setting a settings page may edit: its value, and what it accepts.

    The JSON is {path, values, schema}; the schema lists key, group, label, kind
    (bool|choice|int|text|list), choices, min and help for each key.
    """
    data = config_schema.show()
    if json_mode:
        emit(data, json_mode=True)
        return
    for item in data["schema"]:
        click.echo(f"{item['key']} = {data['values'][item['key']]}")


@config_group.command("set")
@click.argument("key")
@click.argument("value")
@click.option("--dry-run", is_flag=True, help="Check the value and print what would change")
@json_option
def config_set(key: str, value: str, dry_run: bool, json_mode: bool) -> None:
    """Set a config value (lists are comma-separated).

    ui.run_at_startup / ui.start_minimized also update the XDG autostart file
    (same path as desktop install-autostart). With --json a refused value prints
    {ok: false, key, error} and exits 2; --dry-run --json prints one plan document
    ({summary, changes, would_refuse, reason}) and always exits 0.
    """
    try:
        old = set_config_value(key, value, dry_run=dry_run)
    except (KeyError, ValueError) as exc:
        reason = str(exc.args[0]) if exc.args else str(exc)
        if dry_run and json_mode:
            emit({"ok": False, "key": key, "value": value, **refused(reason)}, json_mode=True)
            return
        if json_mode:
            emit({"ok": False, "key": key, "error": reason}, json_mode=True)
            raise SystemExit(int(ExitCode.ERROR)) from exc
        raise click.ClickException(reason) from exc
    if dry_run:
        detail = f"{old if old not in (None, '') else 'empty'} \u2192 {value if value else 'empty'}"
        doc = plan_doc(
            f"Set {key}", [change(key, group="Settings", detail=detail, reversible=True)]
        )
        if json_mode:
            emit(
                {"ok": True, "dry_run": True, "key": key, "value": value, "old": old, **doc},
                json_mode=True,
            )
        else:
            click.echo(f"Would set {key}: {detail}")
        return
    payload = {"ok": True, "key": key, "value": value}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Set {key}={value}")
