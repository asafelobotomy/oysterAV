"""`oyst-cli status summary`: cheap ok/warning/threat state for desktop widgets."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.events import EventLog
from oyst_core.status_summary import build_summary, classify, quarantine_count

NOW = datetime(2026, 11, 11, 12, 0, 0)


def _scan(job_id: str, *, findings: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "job_id": job_id,
        "profile": "quick",
        "paths": ["/home/user/Downloads"],
        "started_at": "2026-11-11T09:00:00",
        "finished_at": "2026-11-11T10:00:00",
        "clean": not findings,
        "findings": findings,
        "pack_errors": [],
        "state": "completed",
    }
    payload.update(extra)
    return payload


def _eicar(path: str = "/home/user/Downloads/eicar.com", **extra: Any) -> dict[str, Any]:
    finding = {"pack": "clamav", "path": path, "threat_name": "Eicar-Test-Signature"}
    finding.update(extra)
    return finding


def _vault(tmp_path: Path, rows: int) -> Path:
    vault = tmp_path / "quarantine"
    vault.mkdir()
    with sqlite3.connect(vault / "vault.db") as conn:
        conn.execute(
            "CREATE TABLE entries (id INTEGER PRIMARY KEY, original_path TEXT, vault_path TEXT, "
            "sha256 TEXT, threat_name TEXT, quarantined_at TEXT, metadata TEXT)"
        )
        for i in range(rows):
            conn.execute(
                "INSERT INTO entries (original_path, vault_path, sha256, quarantined_at) "
                "VALUES (?, ?, ?, ?)",
                (f"/tmp/f{i}", f"{vault}/f{i}", "0" * 64, "2026-11-01T00:00:00"),
            )
    return vault


@pytest.mark.parametrize(
    ("last", "sig", "state", "reason"),
    [
        ({"open_findings_count": 0, "state": "completed"}, 3.0, "ok", None),
        ({"open_findings_count": 2, "state": "completed"}, 3.0, "threat", "2 unresolved findings"),
        (
            {"open_findings_count": 1, "state": "completed"},
            100.0,
            "threat",
            "1 unresolved finding ",
        ),
        (None, 3.0, "warning", "no scan has run yet"),
        ({"open_findings_count": 0, "state": "failed"}, 3.0, "warning", "the last scan failed"),
        ({"open_findings_count": 0, "has_errors": True}, 3.0, "warning", "scanner errors"),
        ({"open_findings_count": 0}, 72.4, "warning", "72 hours old"),
        ({"open_findings_count": 0}, None, "warning", "no virus signatures found"),
    ],
)
def test_classify(
    last: dict[str, Any] | None, sig: float | None, state: str, reason: str | None
) -> None:
    got_state, reasons = classify(last_scan=last, signature_age_hours=sig)
    assert got_state == state
    if reason is None:
        assert reasons == []
    else:
        assert any(reason in r for r in reasons), reasons


def test_summary_reports_threat_from_last_scan(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(_scan("old", findings=[], started_at="2026-11-01T09:00:00"))
    events.save_scan(_scan("new", findings=[_eicar()]))
    data = build_summary(events, vault_dir=_vault(tmp_path, 3), signature_age_hours=5.04, now=NOW)
    assert data["state"] == "threat"
    assert data["last_scan_job_id"] == "new"
    assert data["last_scan_at"] == "2026-11-11T10:00:00"
    assert data["last_scan_age_hours"] == pytest.approx(2.0)
    assert data["open_findings"] == 1
    assert data["signature_age_hours"] == 5.0
    assert data["signatures_stale"] is False
    assert data["quarantine_count"] == 3
    assert data["scanning"] is False
    assert data["schema"] == 1
    json.dumps(data)


def test_quarantined_findings_are_no_longer_threats(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(_scan("q", findings=[_eicar(quarantined=True)]))
    data = build_summary(events, vault_dir=_vault(tmp_path, 1), signature_age_hours=1.0, now=NOW)
    assert data["state"] == "ok"
    assert data["open_findings"] == 0
    assert data["reasons"] == []


def test_summary_without_any_state(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    data = build_summary(events, vault_dir=tmp_path / "missing", signature_age_hours=None, now=NOW)
    assert data["state"] == "warning"
    assert data["last_scan_at"] is None
    assert data["last_scan_age_hours"] is None
    assert data["signatures_stale"] is True
    assert data["quarantine_count"] == 0
    # Read-only: the vault is not created as a side effect.
    assert not (tmp_path / "missing").exists()


def test_quarantine_count_is_read_only_and_tolerant(tmp_path: Path) -> None:
    vault = _vault(tmp_path, 2)
    before = (vault / "vault.db").stat().st_mtime_ns
    assert quarantine_count(vault) == 2
    assert (vault / "vault.db").stat().st_mtime_ns == before
    (vault / "vault.db").write_bytes(b"not a database")
    assert quarantine_count(vault) == 0


def test_summary_reports_a_running_scan(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    with patch.object(EventLog, "active_job", return_value="job-1"):
        data = build_summary(events, vault_dir=tmp_path, signature_age_hours=1.0, now=NOW)
    assert data["scanning"] is True


def test_cli_status_summary_never_scans_or_probes_packs(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    events.save_scan(_scan("cli", findings=[]))

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("status summary must stay cheap")

    with (
        patch("oyst_core.status_summary.EventLog", return_value=events),
        patch("oyst_core.status_summary._vault_dir", return_value=tmp_path / "vault"),
        patch("oyst_core.status_summary._signature_age_hours", return_value=2.0),
        patch("oyst_core.orchestrator.JobOrchestrator.run_scan", forbidden),
        patch("oyst_core.orchestrator.JobOrchestrator.aggregate_status", forbidden),
        patch("oyst_core.doctor_cache.doctor_all", forbidden),
        patch("subprocess.run", forbidden),
        patch("subprocess.Popen", forbidden),
    ):
        result = CliRunner().invoke(cli, ["status", "summary", "--json"])
        human = CliRunner().invoke(cli, ["status", "summary"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["state"] == "ok"
    assert payload["last_scan_job_id"] == "cli"
    assert payload["quarantine_count"] == 0
    assert human.exit_code == 0, human.output
    assert "State: ok" in human.output
    assert "Quarantined files: 0" in human.output


def test_signature_age_uses_file_times_only(tmp_path: Path) -> None:
    import os
    import time

    from oyst_core import status_summary

    db = tmp_path / "clamav-db"
    db.mkdir()
    daily = db / "daily.cvd"
    daily.write_bytes(b"x")
    ten_hours_ago = time.time() - 10 * 3600
    os.utime(daily, (ten_hours_ago, ten_hours_ago))
    with (
        patch("oyst_core.packs.freshclam.clamav_db_dir", return_value=db),
        patch("oyst_core.runtime.bundles.clamav.clamav_db_dir", return_value=db),
        patch("subprocess.run", side_effect=AssertionError("no subprocess")),
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
    ):
        age = status_summary._signature_age_hours()
    assert age == pytest.approx(10.0, abs=0.1)
