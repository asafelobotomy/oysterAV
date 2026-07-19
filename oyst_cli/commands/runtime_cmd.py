"""Runtime management CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option, progress_option
from oyst_cli.output import emit
from oyst_cli.progress import resolve_cli_progress
from oyst_core.runtime.bootstrap import (
    bootstrap_runtime,
    install_pack_runtime,
    remove_pack_runtime,
    runtime_status,
    update_runtime,
)
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap

_INSTALL_EPILOG = """
Examples:
  oyst-cli runtime install lynis --progress
  oyst-cli runtime install --all --json
"""

_BOOTSTRAP_EPILOG = """
Examples:
  oyst-cli runtime bootstrap --json --progress
  oyst-cli runtime bootstrap --no-skip-lynis --json

See also: oyst-cli setup run (first-run), oyst-cli maintenance bootstrap (signatures/baseline).
"""


@click.group("runtime")
def runtime_group() -> None:
    """Manage private pack runtime (Full mode). Prefer runtime bootstrap for one-shot setup."""


@runtime_group.command("status")
@json_option
def runtime_status_cmd(json_mode: bool) -> None:
    """Show runtime installation status and disk usage."""
    status = runtime_status()
    if json_mode:
        emit(status, json_mode=True)
        return
    click.echo(f"Mode: {status['mode']}")
    click.echo(f"Root: {status['root']}")
    disk_raw = status.get("disk_bytes", 0)
    disk_mb = int(disk_raw) // (1024 * 1024) if isinstance(disk_raw, (int, float)) else 0
    click.echo(f"Disk: {disk_mb} MB")
    packs = status.get("packs", {})
    if isinstance(packs, dict):
        for name, info in sorted(packs.items()):
            if isinstance(info, dict):
                origin = info.get("origin") or info.get("source", "?")
                path = info.get("path") or ""
                desc = info.get("description") or ""
                if info.get("installed"):
                    mark = "private" if origin in ("private", "runtime") else "system"
                else:
                    mark = "missing"
                line = f"  {name}: {mark}"
                if path:
                    line += f" · {path}"
                click.echo(line)
                if desc:
                    click.echo(f"      {desc}")


@runtime_group.command("install", epilog=_INSTALL_EPILOG)
@click.argument("pack", required=False)
@click.option("--all", "install_all", is_flag=True, help="Install all runtime packs")
@json_option
@progress_option
def runtime_install(
    pack: str | None,
    install_all: bool,
    json_mode: bool,
    show_progress: bool,
) -> None:
    """Install one pack or all packs into the private runtime (not host packages)."""
    if not install_all and pack is None:
        raise click.ClickException(
            "Specify a pack name or --all\n"
            "  oyst-cli runtime install lynis\n"
            "  oyst-cli runtime install --all",
        )
    on_progress = resolve_cli_progress(show_progress=show_progress, json_mode=json_mode)

    if install_all:
        results = bootstrap_runtime(on_progress=on_progress)
    else:
        assert pack is not None
        results = [install_pack_runtime(pack, on_progress=on_progress)]
    if json_mode:
        emit(results, json_mode=True)
    else:
        for entry in results:
            name = entry.get("pack", pack or "all")
            ok = entry.get("ok")
            click.echo(f"{name}: {'OK' if ok else 'FAILED'} — {entry.get('message', '')}")
    if not all(r.get("ok") for r in results):
        raise SystemExit(2)


@runtime_group.command(
    "remove",
    epilog="""
Examples:
  oyst-cli runtime remove lynis --confirm --json
  oyst-cli runtime remove lynis --confirm --progress
""",
)
@click.argument("pack")
@click.option("--confirm", is_flag=True)
@json_option
@progress_option
def runtime_remove(pack: str, confirm: bool, json_mode: bool, show_progress: bool) -> None:
    """Remove a pack from the private runtime (does not uninstall host packages)."""
    require_confirm(confirm, message="--confirm required to remove a runtime pack")
    on_progress = resolve_cli_progress(show_progress=show_progress, json_mode=json_mode)
    result = remove_pack_runtime(pack, on_progress=on_progress)
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(str(result.get("message", result)))
        removed_raw = result.get("removed")
        removed = removed_raw if isinstance(removed_raw, list) else []
        if removed:
            for path in removed:
                click.echo(f"  removed: {path}")
    if not result.get("ok"):
        raise SystemExit(2)


@runtime_group.command("update")
@json_option
def runtime_update_cmd(json_mode: bool) -> None:
    """Update ClamAV signatures in the runtime database."""
    result = update_runtime()
    if json_mode:
        emit(result, json_mode=True)
    else:
        clamav = result.get("clamav")
        message = result
        if isinstance(clamav, dict):
            message = clamav.get("message", result)
        click.echo(str(message))
    if not result.get("ok"):
        raise SystemExit(2)


@runtime_group.command("bootstrap", epilog=_BOOTSTRAP_EPILOG)
@click.option("--skip-install", is_flag=True, help="Skip runtime pack install")
@click.option("--skip-signatures", is_flag=True, help="Skip signature update")
@click.option("--skip-maintenance", is_flag=True, help="Skip maintenance bootstrap")
@click.option("--skip-lynis/--no-skip-lynis", default=True, show_default=True)
@json_option
@progress_option
def runtime_bootstrap_cmd(
    skip_install: bool,
    skip_signatures: bool,
    skip_maintenance: bool,
    skip_lynis: bool,
    json_mode: bool,
    show_progress: bool,
) -> None:
    """Full runtime one-shot: install packs, update signatures, run maintenance bootstrap."""
    on_progress = resolve_cli_progress(show_progress=show_progress, json_mode=json_mode)
    result = run_full_runtime_bootstrap(
        skip_install=skip_install,
        update_signatures=not skip_signatures,
        run_maintenance=not skip_maintenance,
        skip_lynis=skip_lynis,
        on_progress=on_progress,
    )
    if json_mode:
        emit(result, json_mode=True)
    else:
        click.echo(
            f"Bootstrap: {result.get('steps_ok', 0)}/{result.get('steps_total', 0)} steps OK",
        )
        for step in result.get("steps", []):
            name = step.get("step", "?")
            if step.get("skipped"):
                click.echo(f"  {name}: skipped")
            elif step.get("ok"):
                click.echo(f"  {name}: OK")
            else:
                click.echo(f"  {name}: FAILED — {step.get('message', '')}")
    if not result.get("ok"):
        raise SystemExit(2)
