"""Config commands."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import config_path, get_config_value, load_config, set_config_value


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


@config_group.command("set")
@click.argument("key")
@click.argument("value")
@json_option
def config_set(key: str, value: str, json_mode: bool) -> None:
    """Set a config value.

    ui.run_at_startup / ui.start_minimized also update the XDG autostart file
    (same path as desktop install-autostart).
    """
    try:
        set_config_value(key, value)
    except KeyError as exc:
        raise click.ClickException(str(exc)) from exc
    payload = {"ok": True, "key": key, "value": value}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Set {key}={value}")
