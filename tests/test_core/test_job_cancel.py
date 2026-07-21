"""Tests for job cancel cooperative flag."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.events import EventLog
from oyst_core.models import Finding, FindingSeverity, JobState, PackTier, ScanProfile
from oyst_core.orchestrator import JobOrchestrator


def test_cancel_job_no_active(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)
    result = orch.cancel_job()
    assert result["ok"] is False
    assert result["cancelled"] is False


def test_cancel_requested_between_packs(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)

    pack = MagicMock()
    pack.name = "clamav"
    pack.doctor.return_value = MagicMock(
        installed=True,
        tier=PackTier.REQUIRED,
        install_hint="",
    )

    call_count = {"n": 0}

    def scan_paths(*_a: object, **_k: object) -> list[object]:
        call_count["n"] += 1
        events.request_cancel()
        return []

    pack.scan_paths.side_effect = scan_paths

    with patch.object(orch.registry, "get", return_value=pack):
        result, _code = orch.run_scan(
            profile=ScanProfile.CUSTOM,
            paths=[str(tmp_path)],
            packs=["clamav", "maldet"],
        )
    assert result.state == JobState.CANCELLED
    assert call_count["n"] == 1


def test_cancel_job_with_active_flag(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)
    assert events.acquire_job_lock("job-42")
    result = orch.cancel_job("job-42")
    assert result["ok"] is True
    assert result["cancelled"] is True
    assert events.cancel_requested()


def test_second_cancel_clears_zombie_lock(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)
    assert events.acquire_job_lock("job-zombie")
    assert orch.cancel_job("job-zombie")["ok"] is True
    assert events.active_job() == "job-zombie"
    cleared = orch.cancel_job("job-zombie")
    assert cleared["ok"] is True
    assert cleared.get("cleared") is True
    assert events.active_job() is None


def test_clear_job_force_releases(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)
    assert events.acquire_job_lock("job-clear")
    result = orch.clear_job()
    assert result["ok"] is True
    assert result["cleared"] is True
    assert result["job_id"] == "job-clear"
    assert events.active_job() is None


def test_stale_lock_auto_clears_after_cancel_age(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from datetime import datetime, timedelta

    events = EventLog(db_path=tmp_path / "events.db")
    assert events.acquire_job_lock("job-old")
    events.request_cancel("job-old")
    old = (datetime.now() - timedelta(minutes=11)).isoformat()
    with events._connect() as conn:
        conn.execute("UPDATE job_lock SET started_at = ? WHERE id = 1", (old,))
    assert events.active_job() is None


def test_custom_scan_runs_lynis_via_concert(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)

    lynis = MagicMock()
    lynis.name = "lynis"
    lynis.doctor.return_value = MagicMock(
        installed=True,
        tier=PackTier.RECOMMENDED,
        install_hint="",
    )

    finding = Finding(
        pack="lynis",
        path="system",
        threat_name="hardening-index:72",
        severity=FindingSeverity.INFO,
        message="Hardening index: 72",
    )
    with (
        patch.object(orch.registry, "get", return_value=lynis),
        patch(
            "oyst_core.orchestrator.run_privileged_scan_concert",
            return_value=([finding], [], [{"pack": "lynis", "ok": True}]),
        ) as concert,
    ):
        result, _code = orch.run_scan(
            profile=ScanProfile.CUSTOM,
            paths=[str(tmp_path)],
            packs=["lynis"],
        )

    concert.assert_called_once()
    lynis.scan_paths.assert_not_called()
    assert any(f.pack == "lynis" for f in result.findings)
