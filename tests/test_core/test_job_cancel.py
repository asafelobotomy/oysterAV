"""Tests for job cancel cooperative flag."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.events import EventLog
from oyst_core.models import JobState, PackTier, ScanProfile
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


def test_custom_scan_runs_lynis_via_audit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)

    lynis = MagicMock()
    lynis.name = "lynis"
    lynis.doctor.return_value = MagicMock(
        installed=True,
        tier=PackTier.RECOMMENDED,
        install_hint="",
    )
    lynis.audit.return_value = (True, "hardening ok", 72)

    with patch.object(orch.registry, "get", return_value=lynis):
        result, _code = orch.run_scan(
            profile=ScanProfile.CUSTOM,
            paths=[str(tmp_path)],
            packs=["lynis"],
        )

    lynis.audit.assert_called_once()
    lynis.scan_paths.assert_not_called()
    assert any(f.pack == "lynis" for f in result.findings)
