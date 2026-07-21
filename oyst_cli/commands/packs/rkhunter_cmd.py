"""RKHunter CLI commands."""

from __future__ import annotations

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.output import emit
from oyst_core.pack_jobs import run_rkhunter_resolve
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.packs.rkhunter_resolve import plan_resolve
from oyst_core.privilege import build_rkhunter_resolve_plan, preflight_body, preflight_dict


@click.group("rkhunter")
def rkhunter_group() -> None:
    """Rootkit Hunter."""


@rkhunter_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_status(json_mode: bool) -> None:
    """Installation and version status."""
    emit(RKHunterPack().doctor().model_dump(), json_mode=json_mode)


@rkhunter_group.command("scan")
@click.option("--skip-keypress/--no-skip-keypress", default=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_scan(skip_keypress: bool, json_mode: bool) -> None:
    """Run integrity check (upstream: rkhunter --check)."""
    pack = RKHunterPack()
    ok, output = pack.scan(skip_keypress=skip_keypress)
    findings = pack.parse_findings(output)
    emit({"findings": [f.model_dump() for f in findings], "ok": ok}, json_mode=json_mode)
    raise SystemExit(1 if findings else (0 if ok else 2))


@rkhunter_group.command("update")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_update(json_mode: bool) -> None:
    """Update data files (upstream: rkhunter --update)."""
    ok, msg = RKHunterPack().update()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)


@rkhunter_group.command("propupd")
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_propupd(confirm: bool, json_mode: bool) -> None:
    """Update property baseline (upstream: rkhunter --propupd)."""
    require_confirm(confirm, message="--confirm required to update rkhunter property baseline")
    ok, msg = RKHunterPack().propupd()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    if not ok:
        raise SystemExit(2)
    if not json_mode:
        click.echo("Baseline updated. Only run on trusted systems.")


@rkhunter_group.command("resolve")
@click.option("--threat", "threat_name", required=True, help="Finding threat_name")
@click.option("--path", "path", default="", help="Finding path (script/hidden)")
@click.option("--message", "message", default="", help="Finding message (SSH mapping)")
@click.option("--job-id", "job_id", default="", help="Patch this history job on success")
@click.option("--force", is_flag=True, help="Allow non-package-owned paths")
@click.option("--dry-run", is_flag=True)
@click.option("--confirm", is_flag=True)
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_resolve(
    threat_name: str,
    path: str,
    message: str,
    job_id: str,
    force: bool,
    dry_run: bool,
    confirm: bool,
    json_mode: bool,
) -> None:
    """Whitelist an rkhunter finding in /etc/rkhunter.d/oysterav-whitelist.conf."""
    try:
        resolve_plan = plan_resolve(threat_name, path=path, message=message)
    except ValueError as exc:
        if json_mode:
            emit({"ok": False, "error": str(exc)}, json_mode=True)
        else:
            click.echo(str(exc), err=True)
        raise SystemExit(2) from None

    priv = build_rkhunter_resolve_plan([(resolve_plan.option, resolve_plan.value)])
    if not dry_run:
        if json_mode and not confirm:
            emit(preflight_dict(priv), json_mode=True)
        elif not json_mode:
            click.echo(preflight_body(priv))
            click.echo(resolve_plan.explanation)
        require_confirm(
            confirm,
            message="--confirm required to write rkhunter whitelist overlay",
        )
    elif not json_mode:
        click.echo(resolve_plan.explanation)

    result = run_rkhunter_resolve(
        threat_name,
        path=path,
        message=message,
        force=force,
        dry_run=dry_run,
        job_id=job_id or None,
    )
    if json_mode:
        emit(result, json_mode=True)
    elif not result.get("ok"):
        click.echo(str(result.get("error") or "resolve failed"), err=True)
    elif dry_run:
        click.echo(
            f"dry-run: would set {result.get('option')}={result.get('value')} "
            f"in {result.get('overlay')}"
        )
    else:
        click.echo(f"Updated {result.get('overlay')}: {result.get('option')}={result.get('value')}")
        click.echo("Re-run an integrity/custom scan to verify the warning is gone.")
    raise SystemExit(0 if result.get("ok") else 2)


@rkhunter_group.command("versioncheck")
@click.option("--json", "json_mode", is_flag=True)
def rkhunter_versioncheck(json_mode: bool) -> None:
    """Check for newer rkhunter release (upstream: rkhunter --versioncheck)."""
    ok, msg = RKHunterPack().versioncheck()
    if json_mode:
        emit({"ok": ok, "message": msg}, json_mode=True)
    else:
        click.echo(msg)
    raise SystemExit(0 if ok else 2)
