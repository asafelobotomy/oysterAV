"""Orchestrator scan-concert ingestion tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from oyst_core.models import FindingSeverity
from oyst_core.orchestrator_scan_concert import (
    ingest_scan_concert_steps,
    run_privileged_scan_concert,
)


def test_ingest_lynis_hardening_index(tmp_path: Path) -> None:
    report = tmp_path / "lynis.out"
    report.write_text("Hardening index : 72\nDone\n", encoding="utf-8")
    registry = MagicMock()
    pack = MagicMock()
    registry.get.return_value = pack
    findings, errors = ingest_scan_concert_steps(
        [{"pack": "lynis", "ok": True, "report_path": str(report), "step": "scan-lynis"}],
        registry,
    )
    assert not errors
    assert len(findings) == 1
    assert findings[0].pack == "lynis"
    assert findings[0].threat_name == "hardening-index:72"
    assert findings[0].severity is FindingSeverity.INFO


def test_ingest_uses_parse_findings(tmp_path: Path) -> None:
    report = tmp_path / "rkhunter.out"
    report.write_text("Warning: foo\n", encoding="utf-8")
    registry = MagicMock()
    pack = MagicMock()
    pack.parse_findings.return_value = []
    registry.get.return_value = pack
    findings, errors = ingest_scan_concert_steps(
        [{"pack": "rkhunter", "ok": True, "report_path": str(report)}],
        registry,
    )
    assert not errors and findings == []
    pack.parse_findings.assert_called_once()


def test_run_privileged_scan_concert_one_helper_call() -> None:
    registry = MagicMock()
    with (
        patch(
            "oyst_core.orchestrator_scan_concert.run_privilege_concert",
            return_value=[{"pack": "rkhunter", "ok": True, "step": "scan-rkhunter"}],
        ) as concert,
        patch(
            "oyst_core.orchestrator_scan_concert.ingest_scan_concert_steps",
            return_value=([], []),
        ),
    ):
        findings, errors, steps = run_privileged_scan_concert(
            job_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            privileged_packs=["rkhunter", "chkrootkit"],
            registry=registry,
        )
    assert concert.call_count == 1
    plan = concert.call_args[0][0]
    assert plan.argv1 == "scan-concert"
    assert findings == [] and errors == []
    assert len(steps) == 1
