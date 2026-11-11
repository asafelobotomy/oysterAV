"""Cheap security summary for `oyst-cli status summary` (desktop widgets, uQ).

Reads only local state: the last scan row in the event log, the signature
database mtimes and the quarantine vault's row count. It never runs a scanner,
probes packs, starts a subprocess or asks for privileges, so a status bar can
poll it every few seconds.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from oyst_core.events import EventLog
from oyst_core.health import SIGNATURE_STALE_HOURS

SummaryState = Literal["ok", "warning", "threat"]

SUMMARY_SCHEMA = 1


def quarantine_count(vault_dir: Path) -> int:
    """Number of quarantined files, read-only; 0 when the vault has no database yet."""
    db = vault_dir / "vault.db"
    if not db.is_file():
        return 0
    try:
        conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT COUNT(*) FROM entries").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return 0
    return int(row[0]) if row else 0


def _signature_age_hours() -> float | None:
    from oyst_core.packs.freshclam import FreshclamPack

    return FreshclamPack().signature_age_hours()


def _vault_dir() -> Path:
    from oyst_core.config import load_config

    return load_config().vault_path()


def _age_hours(stamp: str | None, now: datetime) -> float | None:
    if not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if when.tzinfo is not None:
        when = when.astimezone().replace(tzinfo=None)
    return max(0.0, (now - when).total_seconds() / 3600.0)


def classify(
    *,
    last_scan: dict[str, Any] | None,
    signature_age_hours: float | None,
) -> tuple[SummaryState, list[str]]:
    """`threat` while the last scan has open findings; `warning` for anything to look at."""
    reasons: list[str] = []
    state: SummaryState = "ok"
    open_findings = int(last_scan.get("open_findings_count") or 0) if last_scan else 0
    if open_findings > 0:
        state = "threat"
        plural = "s" if open_findings != 1 else ""
        reasons.append(f"{open_findings} unresolved finding{plural} in the last scan")
    if last_scan is None:
        reasons.append("no scan has run yet")
    elif str(last_scan.get("state") or "") == "failed":
        reasons.append("the last scan failed")
    elif last_scan.get("has_errors"):
        reasons.append("the last scan had scanner errors")
    if signature_age_hours is None:
        reasons.append("no virus signatures found")
    elif signature_age_hours > SIGNATURE_STALE_HOURS:
        reasons.append(f"virus signatures are {int(signature_age_hours)} hours old")
    if state == "ok" and reasons:
        state = "warning"
    return state, reasons


def build_summary(
    events: EventLog | None = None,
    *,
    vault_dir: Path | None = None,
    signature_age_hours: float | None | Literal["probe"] = "probe",
    now: datetime | None = None,
) -> dict[str, Any]:
    """The summary dict; arguments exist for tests."""
    events = events or EventLog()
    now = now or datetime.now()
    rows = events.history(limit=1)
    last = rows[0] if rows else None
    sig = _signature_age_hours() if signature_age_hours == "probe" else signature_age_hours
    state, reasons = classify(last_scan=last, signature_age_hours=sig)
    last_at = str(last["finished_at"] or last["started_at"]) if last else None
    return {
        "schema": SUMMARY_SCHEMA,
        "state": state,
        "reasons": reasons,
        "scanning": events.active_job() is not None,
        "last_scan_at": last_at,
        "last_scan_age_hours": _age_hours(last_at, now),
        "last_scan_job_id": last["job_id"] if last else None,
        "last_scan_profile": last["profile"] if last else None,
        "last_scan_state": last["state"] if last else None,
        "open_findings": int(last.get("open_findings_count") or 0) if last else 0,
        "signature_age_hours": None if sig is None else round(sig, 1),
        "signatures_stale": sig is None or sig > SIGNATURE_STALE_HOURS,
        "quarantine_count": quarantine_count(vault_dir or _vault_dir()),
    }
