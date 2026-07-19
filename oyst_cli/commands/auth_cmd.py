"""CLI: polkit passwordless grants for service lifecycle."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.privileged.auth_grant import (
    auth_status,
    grant_service_lifecycle,
    revoke_service_lifecycle,
)
from oyst_core.privileged.install_privileged_helper import helper_status


@click.group("auth")
def auth_group() -> None:
    """Polkit authorization grants for oysterAV privileged helpers."""


@auth_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def auth_status_cmd(json_mode: bool) -> None:
    """Show helper install state and service-lifecycle passwordless grant."""
    payload = {
        "helper": helper_status(),
        "service_lifecycle": auth_status(),
    }
    emit(payload, json_mode=json_mode)


@auth_group.command("grant-service-lifecycle")
@click.option(
    "--user",
    "username",
    default=None,
    help="Unix username to grant (default: current user). Requires root.",
)
@click.option("--json", "json_mode", is_flag=True)
def auth_grant_cmd(username: str | None, json_mode: bool) -> None:
    """Allow service start/stop without password (polkit rules.d; requires root)."""
    result = grant_service_lifecycle(username)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@auth_group.command("revoke-service-lifecycle")
@click.option("--json", "json_mode", is_flag=True)
def auth_revoke_cmd(json_mode: bool) -> None:
    """Remove passwordless service-lifecycle grant (requires root)."""
    result = revoke_service_lifecycle()
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
