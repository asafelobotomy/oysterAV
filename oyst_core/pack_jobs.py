"""Standalone pack job execution with job locking."""

from __future__ import annotations

import uuid

from oyst_core.config import load_config
from oyst_core.events import EventLog
from oyst_core.history_actions import resolve_and_patch
from oyst_core.packs.rkhunter import RKHunterPack


def run_rkhunter_scan() -> dict[str, object]:
    events = EventLog()
    job_id = str(uuid.uuid4())
    if not events.acquire_job_lock(job_id):
        return {
            "ok": False,
            "error": "job already running",
            "findings": [],
        }
    try:
        pack = RKHunterPack()
        status = pack.doctor()
        if not status.installed:
            return {
                "ok": False,
                "error": status.install_hint or "rkhunter not installed",
                "findings": [],
            }
        skip_keypress = load_config().rkhunter.skip_keypress
        ok, output = pack.scan(skip_keypress=skip_keypress)
        findings = [f.model_dump() for f in pack.parse_findings(output)]
        events.log("rkhunter", "scan completed", {"job_id": job_id, "warnings": len(findings)})
        return {
            "ok": ok,
            "findings": findings,
            "warnings_count": len(findings),
            "output_tail": output[-4000:],
        }
    finally:
        events.release_job_lock(job_id)


def run_rkhunter_update() -> dict[str, object]:
    pack = RKHunterPack()
    if not pack.doctor().installed:
        return {"ok": False, "message": "rkhunter not installed"}
    ok, msg = pack.update()
    return {"ok": ok, "message": msg}


def run_rkhunter_propupd() -> dict[str, object]:
    pack = RKHunterPack()
    if not pack.doctor().installed:
        return {"ok": False, "message": "rkhunter not installed"}
    ok, msg = pack.propupd()
    return {"ok": ok, "message": msg}


def run_rkhunter_resolve(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
    force: bool = False,
    dry_run: bool = False,
    job_id: str | None = None,
) -> dict[str, object]:
    try:
        return resolve_and_patch(
            threat_name,
            path=path,
            message=message,
            force=force,
            dry_run=dry_run,
            job_id=job_id,
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
