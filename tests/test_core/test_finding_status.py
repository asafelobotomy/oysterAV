"""Finding open/handled helpers and history handle-open."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from oyst_core.events import EventLog
from oyst_core.finding_status import (
    finding_is_open,
    handled_findings_count,
    open_findings_count,
    scan_is_clean,
    summarize_report_badge,
)
from oyst_core.history_actions import handle_open_findings
from oyst_core.models import Finding, FindingSeverity, ScanProfile, ScanResult


def test_finding_flags_defaults_and_open_helpers() -> None:
    f = Finding(
        pack="clamav",
        path="/tmp/x",
        threat_name="Eicar",
        severity=FindingSeverity.HIGH,
    )
    assert f.quarantined is False
    assert f.resolved is False
    assert finding_is_open(f)
    f.quarantined = True
    assert not finding_is_open(f)
    assert open_findings_count([f]) == 0
    assert handled_findings_count([f]) == 1
    assert scan_is_clean([f])


def test_scan_result_finalize_uses_open_count() -> None:
    result = ScanResult(
        job_id="j",
        profile=ScanProfile.QUICK,
        paths=["/tmp"],
        started_at=datetime.now(),
        findings=[
            Finding(
                pack="clamav",
                path="/tmp/x",
                threat_name="Eicar",
                severity=FindingSeverity.HIGH,
                quarantined=True,
            )
        ],
    )
    result.finalize()
    assert result.clean is True


def test_summarize_report_badge() -> None:
    assert summarize_report_badge([]) == "Clean"
    open_f = {"pack": "clamav", "quarantined": False, "resolved": False}
    assert summarize_report_badge([open_f]) == "1 finding(s)"
    handled = {"pack": "clamav", "quarantined": True, "resolved": False}
    assert summarize_report_badge([handled]) == "1 handled"


def test_handle_open_partial_failure(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(
        {
            "job_id": "job-bulk",
            "profile": "quick",
            "paths": ["/tmp"],
            "started_at": "2026-07-18T10:00:00",
            "finished_at": "2026-07-18T10:01:00",
            "clean": False,
            "findings": [
                {
                    "pack": "clamav",
                    "path": "/tmp/good",
                    "threat_name": "Eicar",
                    "message": "a",
                    "quarantined": False,
                    "resolved": False,
                },
                {
                    "pack": "clamav",
                    "path": "/tmp/missing",
                    "threat_name": "Eicar",
                    "message": "b",
                    "quarantined": False,
                    "resolved": False,
                },
            ],
            "pack_errors": [],
            "state": "completed",
        }
    )

    def fake_quarantine(path: str, threat_name: str = "", **kwargs: object) -> dict:
        if path.endswith("missing"):
            raise FileNotFoundError(path)
        job_id = kwargs.get("job_id")
        if isinstance(job_id, str):
            events.patch_finding(
                job_id,
                pack=str(kwargs.get("pack") or "clamav"),
                path=path,
                threat_name=threat_name,
                message=str(kwargs.get("message") or ""),
                quarantined=True,
            )
        return {"ok": True, "id": 1, "original_path": path, "threat_name": threat_name}

    with (
        patch("oyst_core.history_actions.EventLog", return_value=events),
        patch("oyst_core.history_actions.quarantine_and_patch", side_effect=fake_quarantine),
    ):
        result = handle_open_findings("job-bulk", quarantine=True)

    assert result["quarantined"] == 1
    assert result["ok"] is False
    assert len(result["errors"]) == 1
    got = events.get_scan("job-bulk")
    assert got is not None
    assert got["findings"][0]["quarantined"] is True
    assert got["findings"][1]["quarantined"] is False


def test_handle_open_resolve_uses_batch(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(
        {
            "job_id": "job-resolve",
            "profile": "integrity",
            "paths": ["/"],
            "started_at": "2026-07-18T10:00:00",
            "finished_at": "2026-07-18T10:01:00",
            "clean": False,
            "findings": [
                {
                    "pack": "rkhunter",
                    "path": "system",
                    "threat_name": "rkhunter-ssh",
                    "message": (
                        "Warning: The SSH configuration option 'Protocol' has not been set."
                    ),
                    "quarantined": False,
                    "resolved": False,
                },
                {
                    "pack": "rkhunter",
                    "path": "system",
                    "threat_name": "rkhunter-ssh",
                    "message": (
                        "Warning: The SSH configuration option 'PermitRootLogin' has not been set."
                    ),
                    "quarantined": False,
                    "resolved": False,
                },
            ],
            "pack_errors": [],
            "state": "completed",
        }
    )

    def fake_batch(findings: object, **kwargs: object) -> dict:
        _ = kwargs
        items = []
        assert isinstance(findings, list)
        for raw in findings:
            assert isinstance(raw, dict)
            items.append(
                {
                    "ok": True,
                    "threat_name": raw["threat_name"],
                    "path": raw.get("path") or "",
                    "message": raw.get("message") or "",
                    "option": "ALLOW_SSH_PROT_V1",
                    "value": "2",
                }
            )
        return {"ok": True, "resolved": len(items), "errors": [], "items": items}

    with (
        patch("oyst_core.history_actions.EventLog", return_value=events),
        patch("oyst_core.history_actions.resolve_findings_batch", side_effect=fake_batch) as batch,
    ):
        result = handle_open_findings("job-resolve", resolve=True)

    assert batch.call_count == 1
    assert result["resolved"] == 2
    assert result["ok"] is True
    got = events.get_scan("job-resolve")
    assert got is not None
    assert all(f["resolved"] for f in got["findings"])
