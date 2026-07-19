"""Orchestrated scan command."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.config import load_config
from oyst_core.models import ScanProfile
from oyst_core.orchestrator import JobOrchestrator

_SCAN_EPILOG = """
Examples:
  oyst-cli scan ~/Downloads --profile quick --json
  oyst-cli scan / --profile integrity --json
  oyst-cli scan --profile custom --packs clamav,rkhunter ~/Downloads
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
@json_option
def scan_cmd(
    paths: tuple[str, ...],
    profile: str | None,
    packs: str | None,
    quarantine: bool,
    backend: str | None,
    json_mode: bool,
) -> None:
    """Run profile-driven multi-pack scan. Exit 3 if another job is already running."""
    cfg = load_config()
    resolved_profile = profile or cfg.scan.profile
    resolved_backend = backend or cfg.scan.backend
    pack_list = [p.strip() for p in packs.split(",")] if packs else None
    path_list = list(paths) if paths else None
    orch = JobOrchestrator()
    result, code = orch.run_scan(
        profile=ScanProfile(resolved_profile),
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
