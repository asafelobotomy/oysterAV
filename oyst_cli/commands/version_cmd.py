"""Show installed oysterAV version and optional GitHub Release check."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core import __version__
from oyst_core.app_release import RELEASES_PAGE_URL, check_app_update


@click.command("version")
@click.option(
    "--check",
    "do_check",
    is_flag=True,
    help="Compare installed version to the latest GitHub Release",
)
@json_option
def version_cmd(do_check: bool, json_mode: bool) -> None:
    """Print oysterAV version; optionally check GitHub Releases for updates."""
    if not do_check:
        payload = {
            "ok": True,
            "version": __version__,
            "releases_url": RELEASES_PAGE_URL,
        }
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(f"oysterAV {__version__}")
        return

    result = check_app_update(force=True)
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(str(result.get("message") or f"oysterAV {__version__}"))
    if not result.get("ok"):
        raise SystemExit(2)
    if result.get("update"):
        raise SystemExit(1)
