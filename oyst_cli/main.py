"""oyst-cli entry point."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.commands.audit_cmd import audit_group
from oyst_cli.commands.auth_cmd import auth_group
from oyst_cli.commands.config_cmd import config_group
from oyst_cli.commands.desktop_cmd import desktop_group
from oyst_cli.commands.doctor import doctor_cmd
from oyst_cli.commands.install_helper_cmd import helper_status_cmd, install_helper_cmd
from oyst_cli.commands.job_cmd import job_group
from oyst_cli.commands.maintenance import maintenance_group
from oyst_cli.commands.news_cmd import news_group
from oyst_cli.commands.pack_install_cmd import packs_group
from oyst_cli.commands.packs import (
    chkrootkit_group,
    clamav_group,
    clamonacc_group,
    fail2ban_group,
    fangfrisch_group,
    firewall_group,
    freshclam_group,
    lynis_group,
    maldet_group,
    rkhunter_group,
    unhide_group,
)
from oyst_cli.commands.quarantine import quarantine_group
from oyst_cli.commands.runtime_cmd import runtime_group
from oyst_cli.commands.scan import scan_cmd
from oyst_cli.commands.schedule_cmd import schedule_group
from oyst_cli.commands.services_cmd import services_group
from oyst_cli.commands.setup_cmd import setup_group
from oyst_cli.commands.status import history_group, status_group
from oyst_cli.commands.terminal_cmd import terminal_group
from oyst_cli.commands.updates_cmd import updates_group
from oyst_cli.commands.virusevent_cmd import virusevent_group
from oyst_core.logging_util import setup_logging
from oyst_core.serve import SCHEMA_VERSION, RpcServer


def _is_terminal_mgmt(ctx: click.Context) -> bool:
    if ctx.invoked_subcommand == "terminal":
        return True
    return "terminal" in (ctx.command_path or "").split()


def _cli_label(ctx: click.Context) -> str:
    """Best-effort command label (result callback runs on the root context)."""
    parts: list[str] = [ctx.info_name or "cli"]
    if ctx.invoked_subcommand:
        parts.append(ctx.invoked_subcommand)
    # Prefer click path; fall back to argv when nested (e.g. audit list).
    import sys

    argv_parts = [p for p in sys.argv[1:] if p not in {"-v", "--verbose"}]
    if (
        argv_parts
        and not argv_parts[0].endswith(".py")
        and not argv_parts[0].startswith("tests/")
        and argv_parts[0] not in {"-c", "-m"}
    ):
        return "cli " + " ".join(argv_parts)
    return " ".join(parts)


@click.group()
@click.option("-v", "--verbose", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """oyst-cli — Linux security orchestrator backend for oysterAV."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@cli.result_callback()
@click.pass_context
def _cli_finished(ctx: click.Context, result: object, **_kwargs: object) -> object:
    if not _is_terminal_mgmt(ctx):
        try:
            from oyst_core.terminal_log import log_structured

            code = getattr(ctx, "exit_code", None)
            if code is None:
                code = 0
            label = _cli_label(ctx)
            log_structured(
                "cli",
                "cli.finish",
                f"{label} finished (exit {code})",
                {"exit_code": code},
            )
        except Exception:  # noqa: BLE001
            pass
    return result


_SERVE_EPILOG = """
Examples:
  oyst-cli serve
  oyst-cli serve --foreground
  oyst-cli serve --socket /tmp/oyst.sock
"""


@cli.command("serve", epilog=_SERVE_EPILOG)
@click.option("--socket", type=click.Path(), default=None)
@click.option(
    "--schema-version",
    default=SCHEMA_VERSION,
    type=int,
    help=f"Reject if not equal to server schema (currently {SCHEMA_VERSION})",
)
@click.option(
    "--foreground",
    is_flag=True,
    help="Kept for compatibility; serve always runs in the foreground",
)
def serve_cmd(socket: str | None, schema_version: int, foreground: bool) -> None:
    """Start JSON-RPC backend for GUI clients (always foreground)."""
    del foreground  # accepted for GUI-contract / docs compatibility
    if schema_version != SCHEMA_VERSION:
        click.echo(
            f"Error: unsupported schema version {schema_version} "
            f"(server schema is {SCHEMA_VERSION})",
            err=True,
        )
        raise SystemExit(2)
    path = Path(socket) if socket else None
    click.echo(f"oyst-cli serve on {path or 'default socket'} (schema v{SCHEMA_VERSION})")
    RpcServer(path).serve_forever()


def _register_commands() -> None:
    cli.add_command(doctor_cmd)
    cli.add_command(status_group)
    cli.add_command(history_group)
    cli.add_command(scan_cmd)
    cli.add_command(job_group)
    cli.add_command(virusevent_group)
    cli.add_command(maintenance_group)
    cli.add_command(quarantine_group)
    cli.add_command(config_group)
    cli.add_command(schedule_group)
    cli.add_command(desktop_group)
    cli.add_command(news_group)
    cli.add_command(updates_group)
    cli.add_command(setup_group)
    cli.add_command(audit_group)
    cli.add_command(terminal_group)
    cli.add_command(install_helper_cmd)
    cli.add_command(helper_status_cmd)
    cli.add_command(services_group)
    cli.add_command(auth_group)
    cli.add_command(packs_group)
    cli.add_command(runtime_group)
    for grp in (
        clamav_group,
        freshclam_group,
        fangfrisch_group,
        clamonacc_group,
        rkhunter_group,
        chkrootkit_group,
        lynis_group,
        maldet_group,
        firewall_group,
        fail2ban_group,
        unhide_group,
    ):
        cli.add_command(grp)


_register_commands()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
