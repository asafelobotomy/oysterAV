"""Quarantine commands."""

from __future__ import annotations

from pathlib import Path

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.models import ExitCode
from oyst_core.plan import change, plan_doc, refused
from oyst_core.quarantine import QuarantineVault


def _vault_size(entry: object) -> int | None:
    """Bytes of the vaulted copy, or None when it is missing."""
    try:
        return Path(str(getattr(entry, "vault_path", ""))).stat().st_size
    except OSError:
        return None


def _where(entry: object) -> tuple[str, str]:
    """(file name, "path (threat)") of an entry, for a plan."""
    path = str(getattr(entry, "original_path", ""))
    threat = str(getattr(entry, "threat_name", "") or "unknown threat")
    return Path(path).name or path, f"{path} ({threat})"


# Vault errors surfaced as a clean failure (never exit 1, which means threats found).
_VAULT_ERRORS = (KeyError, OSError, ValueError, RuntimeError)

_DELETE_EPILOG = """
Examples:
  oyst-cli quarantine delete 1 --dry-run --json
  oyst-cli quarantine delete 1 --confirm --json
"""


def _fail(entry_id: int, exc: BaseException | str, *, json_mode: bool) -> None:
    if isinstance(exc, KeyError):
        message = f"entry {entry_id} not found"
    elif isinstance(exc, FileNotFoundError):
        message = f"vault file missing for entry {entry_id}: {exc}"
    else:
        message = str(exc) or type(exc).__name__
    if json_mode:
        emit({"ok": False, "entry_id": entry_id, "error": message}, json_mode=True)
    else:
        click.echo(f"Error: {message}", err=True)
    raise SystemExit(int(ExitCode.ERROR))


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
            _fail(entry_id, f"entry {entry_id} not found", json_mode=json_mode)
            return
        name, where = _where(entry)
        payload = {
            "ok": True,
            "dry_run": True,
            "entry_id": entry_id,
            "dest": entry.original_path,
            **plan_doc(
                f"Restore {name}",
                [
                    change(
                        name,
                        group="Back to where it was found",
                        detail=where,
                        size=_vault_size(entry),
                    )
                ],
            ),
        }
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(f"Would restore entry {entry_id} to {entry.original_path}")
        return
    try:
        dest = QuarantineVault().restore(entry_id)
    except _VAULT_ERRORS as exc:
        _fail(entry_id, exc, json_mode=json_mode)
        return
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
            _fail(entry_id, f"entry {entry_id} not found", json_mode=json_mode)
            return
        name, where = _where(entry)
        payload = {
            "ok": True,
            "dry_run": True,
            "entry_id": entry_id,
            **plan_doc(
                f"Delete {name} for good",
                [
                    change(
                        name,
                        group="Deleted for good",
                        detail=where,
                        size=_vault_size(entry),
                        reversible=False,
                    )
                ],
            ),
        }
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(f"Would delete entry {entry_id}")
        return
    try:
        QuarantineVault().delete(entry_id)
    except _VAULT_ERRORS as exc:
        _fail(entry_id, exc, json_mode=json_mode)
        return
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
@click.option("--dry-run", is_flag=True, help="Print what would be moved; move nothing")
@json_option
def add_cmd(
    path: str,
    threat: str,
    job_id: str,
    pack: str,
    message: str,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    from oyst_core.history_actions import quarantine_and_patch

    require_confirm(confirm, dry_run=dry_run, message="--confirm required to quarantine a file")
    if dry_run:
        target = Path(path).expanduser()
        try:
            size: int | None = target.stat().st_size
        except OSError:
            size = None
        doc = (
            plan_doc(
                f"Quarantine {target.name or path}",
                [
                    change(
                        target.name or path,
                        group="Moved to the quarantine vault",
                        detail=f"{target} ({threat})",
                        size=size,
                        reversible=True,
                    )
                ],
            )
            if size is not None
            else refused(f"{path} is not there any more.")
        )
        if json_mode:
            emit({"ok": True, "dry_run": True, "path": path, **doc}, json_mode=True)
        else:
            click.echo(f"Would quarantine {path}" if size is not None else doc["reason"])
        return
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
                **(
                    plan_doc(
                        f"Delete {len(orphans)} stray vault file(s)",
                        [
                            change(
                                Path(str(o)).name or str(o),
                                group="Stray vault files",
                                detail=str(o),
                                reversible=False,
                            )
                            for o in orphans
                        ],
                    )
                    if orphans
                    else refused("The vault has no stray files.")
                ),
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
