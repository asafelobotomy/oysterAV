"""``oyst-cli hardening set apply|revert``: the Security page's Harden button (sysctl drop-in)."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit


@click.group("hardening")
def hardening_group() -> None:
    """Kernel hardening oysterAV can apply (read the checks with `status hardening`)."""


@hardening_group.command(
    "set",
    epilog="""
Examples:
  oyst-cli hardening set apply --dry-run --json
  oyst-cli hardening set apply --confirm --json
  oyst-cli hardening set revert --confirm --json
""",
)
@click.argument("action", type=click.Choice(["apply", "revert"], case_sensitive=True))
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True, help="Print what would change; change nothing")
@click.option("--json", "json_mode", is_flag=True)
def hardening_set_cmd(action: str, confirm: bool, dry_run: bool, json_mode: bool) -> None:
    """Write (apply) or remove (revert) /etc/sysctl.d/90-oysterav-hardening.conf via oyst-helper."""
    from oyst_core.hardening_fix import harden_plan, run_harden

    require_confirm(
        confirm, dry_run=dry_run, message="--confirm required to change kernel settings"
    )
    if dry_run:
        doc = harden_plan(action)
        if json_mode:
            emit({"ok": True, "dry_run": True, "action": action, **doc}, json_mode=True)
        else:
            click.echo(doc["summary"])
            for item in doc["changes"]:
                click.echo(f"  - {item['label']}")
        return
    result = run_harden(action)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)
