"""Pack install CLI commands."""

from __future__ import annotations

import click

from oyst_cli.options import json_option, progress_option
from oyst_cli.output import emit
from oyst_cli.progress import resolve_cli_progress
from oyst_core.pack_install import install_pack, list_packs


@click.group("packs")
def packs_group() -> None:
    """Security pack management."""


@packs_group.command(
    "install",
    epilog="""
Examples:
  oyst-cli packs install clamav --confirm-aur --json
  oyst-cli packs install lynis --progress
""",
)
@click.argument("name")
@click.option("--confirm-aur", is_flag=True, help="Confirm AUR install without prompting")
@json_option
@progress_option
def packs_install(name: str, confirm_aur: bool, json_mode: bool, show_progress: bool) -> None:
    """Install a pack (full mode → private runtime; lite → distro packages)."""
    on_progress = resolve_cli_progress(show_progress=show_progress, json_mode=json_mode)
    result = install_pack(name, confirm_aur=confirm_aur, on_progress=on_progress)
    emit(result.model_dump(), json_mode=json_mode)
    if result.ok:
        raise SystemExit(0)
    if result.mode in ("manual", "aur_confirm"):
        raise SystemExit(4)
    raise SystemExit(2)


@packs_group.command("list")
@json_option
def packs_list(json_mode: bool) -> None:
    """List all packs with install status."""
    packs = list_packs()
    emit(packs, json_mode=json_mode)
