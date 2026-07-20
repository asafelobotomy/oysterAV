"""Scan history export helpers."""

from __future__ import annotations

from pathlib import Path

from oyst_core.events import EventLog
from oyst_core.history_export import (
    export_all_scans_to_path,
    export_scan_to_path,
    format_scan_markdown,
)


def _sample(job_id: str = "job-1") -> dict:
    return {
        "job_id": job_id,
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
                "severity": "high",
                "quarantined": False,
                "resolved": False,
            }
        ],
        "pack_errors": [],
        "state": "completed",
    }


def test_format_scan_markdown_includes_finding() -> None:
    text = format_scan_markdown(_sample())
    assert "job-1" in text
    assert "Eicar FOUND" in text
    assert "/tmp/eicar" in text


def test_export_scan_json_and_md(tmp_path: Path, monkeypatch: object) -> None:
    db = tmp_path / "events.db"
    events = EventLog(db_path=db)
    events.save_scan(_sample())
    monkeypatch.setattr("oyst_core.history_export.EventLog", lambda: events)
    monkeypatch.setenv("HOME", str(tmp_path))
    exports = tmp_path / ".local" / "share" / "oysterav" / "exports"
    exports.mkdir(parents=True, exist_ok=True)

    json_path = exports / "one.json"
    result = export_scan_to_path("job-1", json_path, fmt="json")
    assert result["ok"] is True
    assert json_path.is_file()
    assert "Eicar" in json_path.read_text(encoding="utf-8")

    md_path = exports / "one.md"
    result_md = export_scan_to_path("job-1", md_path, fmt="md")
    assert result_md["ok"] is True
    assert "Eicar FOUND" in md_path.read_text(encoding="utf-8")

    outside = tmp_path / "outside.json"
    bad = export_scan_to_path("job-1", outside, fmt="json")
    assert bad["ok"] is False
    assert (
        "exports" in str(bad.get("error") or "").lower()
        or "export" in str(bad.get("error") or "").lower()
    )


def test_export_all_scans(tmp_path: Path, monkeypatch: object) -> None:
    db = tmp_path / "events.db"
    events = EventLog(db_path=db)
    events.save_scan(_sample("job-1"))
    events.save_scan(_sample("job-2"))
    monkeypatch.setattr("oyst_core.history_export.EventLog", lambda: events)
    monkeypatch.setenv("HOME", str(tmp_path))
    exports = tmp_path / ".local" / "share" / "oysterav" / "exports"
    exports.mkdir(parents=True, exist_ok=True)

    out = exports / "all.json"
    result = export_all_scans_to_path(out, fmt="json")
    assert result["ok"] is True
    assert result["count"] == 2
    text = out.read_text(encoding="utf-8")
    assert "job-1" in text and "job-2" in text
