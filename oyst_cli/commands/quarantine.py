"""Quarantine commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.quarantine import QuarantineVault

_DELETE_EPILOG = """
Examples:
  oyst-cli quarantine delete 1 --dry-run --json
  oyst-cli quarantine delete 1 --confirm --json
"""


@click.group("quarantine")
def quarantine_group() -> None:
    """Manage quarantined files."""


@quarantine_group.command("list")
@json_option
def list_cmd(json_mode: bool) -> None:
    entries = QuarantineVault().list_entries()
    emit([e.model_dump(mode="json") for e in entries], json_mode=json_mode)


@quarantine_group.command("show")
@click.argument("entry_id", type=int)
@json_option
def show_cmd(entry_id: int, json_mode: bool) -> None:
    entry = QuarantineVault().get(entry_id)
    if not entry:
        raise click.ClickException(f"entry {entry_id} not found")
    emit(entry.model_dump(mode="json"), json_mode=json_mode)


@quarantine_group.command(
    "restore",
    epilog="""
Examples:
  oyst-cli quarantine restore 1 --dry-run --json
  oyst-cli quarantine restore 1 --confirm --json
""",
)
@click.argument("entry_id", type=int)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@json_option
def restore_cmd(entry_id: int, confirm: bool, dry_run: bool, json_mode: bool) -> None:
    require_confirm(
        confirm,
        dry_run=dry_run,
        message="--confirm required to restore a quarantined file",
    )
    if dry_run:
        entry = QuarantineVault().get(entry_id)
        if not entry:
            raise click.ClickException(f"entry {entry_id} not found")
        payload = {
            "ok": True,
            "dry_run": True,
            "entry_id": entry_id,
            "dest": entry.original_path,
        }
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(f"Would restore entry {entry_id} to {entry.original_path}")
        return
    dest = QuarantineVault().restore(entry_id)
    payload = {"ok": True, "entry_id": entry_id, "dest": str(dest)}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Restored to {dest}")


@quarantine_group.command("delete", epilog=_DELETE_EPILOG)
@click.argument("entry_id", type=int)
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@json_option
def delete_cmd(entry_id: int, confirm: bool, dry_run: bool, json_mode: bool) -> None:
    require_confirm(
        confirm,
        dry_run=dry_run,
        message="--confirm required to delete a quarantined file",
    )
    if dry_run:
        entry = QuarantineVault().get(entry_id)
        if not entry:
            raise click.ClickException(f"entry {entry_id} not found")
        payload = {"ok": True, "dry_run": True, "entry_id": entry_id}
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(f"Would delete entry {entry_id}")
        return
    QuarantineVault().delete(entry_id)
    payload = {"ok": True, "entry_id": entry_id}
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(f"Deleted entry {entry_id}")


@quarantine_group.command("add")
@click.argument("path")
@click.option("--threat", default="manual")
@click.option("--job-id", "job_id", default="", help="Patch this history job on success")
@click.option("--pack", default="", help="Finding pack when patching history")
@click.option("--message", default="", help="Finding message when patching history")
@click.option("--confirm", is_flag=True)
@json_option
def add_cmd(
    path: str,
    threat: str,
    job_id: str,
    pack: str,
    message: str,
    confirm: bool,
    json_mode: bool,
) -> None:
    from oyst_core.history_actions import quarantine_and_patch

    require_confirm(confirm, message="--confirm required to quarantine a file")
    payload = quarantine_and_patch(
        path,
        threat,
        job_id=job_id or None,
        pack=pack,
        message=message,
    )
    if json_mode:
        emit(payload, json_mode=True)
    else:
        click.echo(
            f"Quarantined id={payload.get('id')} sha256={str(payload.get('sha256', ''))[:16]}..."
        )


@quarantine_group.command("verify")
@json_option
def verify_cmd(json_mode: bool) -> None:
    vault = QuarantineVault()
    bad = vault.verify()
    orphans = vault.list_orphans()
    emit(
        {
            "invalid_entries": bad,
            "orphans": orphans,
            "orphan_count": len(orphans),
            "ok": len(bad) == 0 and len(orphans) == 0,
        },
        json_mode=json_mode,
    )


@quarantine_group.command(
    "reconcile",
    epilog="""
Examples:
  oyst-cli quarantine reconcile --json
  oyst-cli quarantine reconcile --delete-orphans --confirm --json
""",
)
@click.option("--delete-orphans", is_flag=True, help="Delete vault files with no DB row")
@click.option("--confirm", is_flag=True)
@click.option("--dry-run", is_flag=True)
@json_option
def reconcile_cmd(
    delete_orphans: bool,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    vault = QuarantineVault()
    orphans = vault.list_orphans()
    if delete_orphans:
        require_confirm(
            confirm,
            dry_run=dry_run,
            message="--confirm required to delete quarantine orphans",
        )
        if dry_run:
            payload = {
                "ok": True,
                "dry_run": True,
                "orphans": orphans,
                "deleted": [],
            }
            emit(payload, json_mode=json_mode)
            if not json_mode:
                click.echo(f"Would delete {len(orphans)} orphan(s)")
            return
        payload = vault.reconcile_orphans(delete=True)
    else:
        payload = {"ok": True, "orphans": orphans, "deleted": []}
    emit(payload, json_mode=json_mode)
    if not json_mode:
        orphans_out = payload.get("orphans") or []
        deleted_out = payload.get("deleted") or []
        assert isinstance(orphans_out, list)
        assert isinstance(deleted_out, list)
        click.echo(f"Orphans: {len(orphans_out)}")
        if deleted_out:
            click.echo(f"Deleted: {len(deleted_out)}")
