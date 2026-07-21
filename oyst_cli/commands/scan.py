"""Orchestrated scan command."""

from __future__ import annotations

import uuid

import click

from oyst_cli.confirm import require_confirm
from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import load_config
from oyst_core.models import PROFILE_AUDIT_PACKS, PROFILE_PACKS, ScanProfile
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.privilege import build_scan_privileged_plan, preflight_body, preflight_dict

_SCAN_EPILOG = """
Examples:
  oyst-cli scan ~/Downloads --profile quick --json
  oyst-cli scan / --profile integrity --confirm --json
  oyst-cli scan --profile custom --packs clamav,rkhunter ~/Downloads --confirm
  oyst-cli scan / --profile integrity --dry-run --json
"""


@click.command("scan", epilog=_SCAN_EPILOG)
@click.argument("paths", nargs=-1)
@click.option(
    "--profile",
    type=click.Choice([p.value for p in ScanProfile]),
    default=None,
    help="Scan profile (default: scan.profile from config)",
)
@click.option("--packs", default=None, help="Comma-separated pack override")
@click.option("--quarantine", is_flag=True)
@click.option(
    "--backend",
    default=None,
    help="ClamAV backend auto|clamd|clamscan (default: scan.backend from config)",
)
@click.option("--confirm", is_flag=True, help="Confirm when privileged scanners need elevation")
@click.option("--dry-run", is_flag=True, help="Print privilege plan only; do not scan")
@json_option
def scan_cmd(
    paths: tuple[str, ...],
    profile: str | None,
    packs: str | None,
    quarantine: bool,
    backend: str | None,
    confirm: bool,
    dry_run: bool,
    json_mode: bool,
) -> None:
    """Run profile-driven multi-pack scan. Exit 3 if another job is already running."""
    cfg = load_config()
    resolved_profile = profile or cfg.scan.profile
    resolved_backend = backend or cfg.scan.backend
    pack_list = [p.strip() for p in packs.split(",")] if packs else None
    path_list = list(paths) if paths else None
    scan_profile = ScanProfile(resolved_profile)
    if pack_list is None:
        selected = list(PROFILE_PACKS.get(scan_profile, []))
        selected.extend(PROFILE_AUDIT_PACKS.get(scan_profile, []))
    else:
        selected = pack_list
    plan = build_scan_privileged_plan(selected, job_id=str(uuid.uuid4()))
    if plan.needs_elevation:
        if json_mode and (dry_run or not confirm):
            emit(preflight_dict(plan), json_mode=True)
        elif not json_mode:
            click.echo(preflight_body(plan))
        if dry_run:
            raise SystemExit(0)
        require_confirm(
            confirm,
            message="--confirm required when integrity/audit scanners need elevation",
        )
    elif dry_run:
        payload = preflight_dict(plan)
        if json_mode:
            emit(payload, json_mode=True)
        else:
            click.echo(preflight_body(plan))
        raise SystemExit(0)

    orch = JobOrchestrator()
    result, code = orch.run_scan(
        profile=scan_profile,
        paths=path_list,
        packs=pack_list,
        backend=resolved_backend,
        quarantine=quarantine,
    )
    if json_mode:
        emit(result.model_dump(mode="json"), json_mode=True)
    else:
        click.echo(f"Scan {result.job_id}: {'clean' if result.clean else 'threats found'}")
        for f in result.findings:
            click.echo(f"  [{f.pack}] {f.path}: {f.threat_name}")
        for err in result.pack_errors:
            click.echo(f"  error [{err.pack}]: {err.error}", err=True)
    raise SystemExit(int(code))
