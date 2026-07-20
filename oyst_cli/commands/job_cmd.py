"""Job control commands (cancel / clear active scan lock)."""

from __future__ import annotations

import click

from oyst_cli.output import emit
from oyst_core.orchestrator import JobOrchestrator


@click.group("job")
def job_group() -> None:
    """Background / active job control."""


@job_group.command("cancel")
@click.option("--job-id", default=None, help="Optional job id (defaults to active job).")
@click.option(
    "--force",
    is_flag=True,
    help="Force-clear the job lock (use when no scan is actually running).",
)
@click.option("--json", "json_mode", is_flag=True)
def job_cancel_cmd(job_id: str | None, force: bool, json_mode: bool) -> None:
    """Request cancel of the active scan job (cooperative between packs)."""
    result = JobOrchestrator().cancel_job(job_id, force=force)
    emit(result, json_mode=json_mode)
    if not result.get("ok"):
        raise SystemExit(2)


@job_group.command("clear")
@click.option("--json", "json_mode", is_flag=True)
def job_clear_cmd(json_mode: bool) -> None:
    """Force-clear a stuck job lock (zombie 'scan in progress' banner)."""
    result = JobOrchestrator().clear_job()
    emit(result, json_mode=json_mode)


@job_group.command("status")
@click.option("--json", "json_mode", is_flag=True)
def job_status_cmd(json_mode: bool) -> None:
    """Show live progress for the active scan job (if any)."""
    result = JobOrchestrator().job_status()
    emit(result, json_mode=json_mode)
