"""EventLog scan history list/get normalization."""

from __future__ import annotations

from pathlib import Path

from oyst_core.events import EventLog


def test_history_normalizes_paths_and_state(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(
        {
            "job_id": "job-1",
            "profile": "quick",
            "paths": ["/tmp/a", "/tmp/b"],
            "started_at": "2026-07-18T10:00:00",
            "finished_at": "2026-07-18T10:01:00",
            "clean": False,
            "findings": [{"pack": "clamav", "path": "/tmp/a", "threat_name": "Eicar"}],
            "pack_errors": [],
            "state": "cancelled",
        }
    )
    rows = events.history(limit=5)
    assert len(rows) == 1
    row = rows[0]
    assert row["job_id"] == "job-1"
    assert row["paths"] == ["/tmp/a", "/tmp/b"]
    assert row["clean"] is False
    assert row["findings_count"] == 1
    assert row["state"] == "cancelled"
    assert row["has_errors"] is False
    assert "result_json" not in row


def test_get_scan_returns_full_result(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    payload = {
        "job_id": "job-2",
        "profile": "quick",
        "paths": ["~/Downloads"],
        "started_at": "2026-07-18T11:00:00",
        "finished_at": "2026-07-18T11:02:00",
        "clean": True,
        "findings": [],
        "pack_errors": [{"pack": "rkhunter", "error": "timeout"}],
        "state": "completed",
    }
    events.save_scan(payload)
    got = events.get_scan("job-2")
    assert got is not None
    assert got["job_id"] == "job-2"
    assert got["pack_errors"] == [{"pack": "rkhunter", "error": "timeout"}]
    rows = events.history(limit=1)
    assert rows[0]["has_errors"] is True
    assert events.get_scan("missing") is None


def test_patch_finding_marks_quarantined_and_clean(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(
        {
            "job_id": "job-q",
            "profile": "quick",
            "paths": ["/tmp"],
            "started_at": "2026-07-18T10:00:00",
            "finished_at": "2026-07-18T10:01:00",
            "clean": False,
            "findings": [
                {
                    "pack": "clamav",
                    "path": "/tmp/eicar",
                    "threat_name": "Eicar",
                    "message": "Eicar FOUND",
                    "quarantined": False,
                    "resolved": False,
                }
            ],
            "pack_errors": [],
            "state": "completed",
        }
    )
    patch = events.patch_finding(
        "job-q",
        pack="clamav",
        path="/tmp/eicar",
        threat_name="Eicar",
        message="Eicar FOUND",
        quarantined=True,
    )
    assert patch["ok"] is True
    got = events.get_scan("job-q")
    assert got is not None
    assert got["findings"][0]["quarantined"] is True
    assert got["clean"] is True
    rows = events.history(limit=1)
    assert rows[0]["open_findings_count"] == 0
    assert rows[0]["findings_count"] == 1


def test_history_defaults_state_when_result_missing(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    with events._connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_history (
                job_id, profile, paths, started_at, finished_at,
                clean, findings_count, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy",
                "quick",
                '["/tmp"]',
                "2026-07-18T12:00:00",
                None,
                1,
                0,
                None,
            ),
        )
    rows = events.history(limit=1)
    assert rows[0]["state"] == "completed"
    assert rows[0]["paths"] == ["/tmp"]


def test_delete_scan_and_delete_all(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    for job_id in ("a", "b"):
        events.save_scan(
            {
                "job_id": job_id,
                "profile": "quick",
                "paths": ["/tmp"],
                "started_at": "2026-07-18T10:00:00",
                "finished_at": "2026-07-18T10:01:00",
                "clean": True,
                "findings": [],
                "pack_errors": [],
                "state": "completed",
            }
        )
    assert events.delete_scan("a")["deleted"] == 1
    assert events.get_scan("a") is None
    assert events.get_scan("b") is not None
    assert events.delete_all_scans()["deleted"] == 1
    assert events.history(limit=10) == []
    assert events.delete_scan("missing")["ok"] is False
