"""Job control commands (cancel active scan)."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.orchestrator import JobOrchestrator


@click.group("job")
def job_group() -> None:
    """Background / active job control."""


@job_group.command("cancel")
@click.option("--job-id", default=None, help="Optional job id (defaults to active job).")
@click.option("--json", "json_mode", is_flag=True)
def job_cancel_cmd(job_id: str | None, json_mode: bool) -> None:
    """Request cancel of the active scan job (cooperative between packs)."""
    result = JobOrchestrator().cancel_job(job_id)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@job_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def job_status_cmd(json_mode: bool) -> None:
    """Show live progress for the active scan job (if any)."""
    result = JobOrchestrator().job_status()
    emit(result, json_mode=json_mode)
