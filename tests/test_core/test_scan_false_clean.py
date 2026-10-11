"""Audit S1-S3: scans must never read as clean when packs failed or output is tricky."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.models import PackError, PartialScanError, ScanProfile, ScanResult
from oyst_core.orchestrator_scan_concert import ingest_scan_concert_steps
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.privileged.runner import CommandResult

_SUMMARY = "----------- SCAN SUMMARY -----------\nInfected files: 1\n"


def _parse(stdout: str) -> list[tuple[str, str]]:
    findings = ClamAVPack().parse_findings(CommandResult(1, stdout, ""))
    return [(f.path, f.threat_name) for f in findings]


# --- S1: denied / failed privileged concert -------------------------------------------


def test_denied_concert_marks_every_requested_pack_failed() -> None:
    steps = [
        {"step": "scan-privileged", "ok": False, "message": "Not authorized", "soft_fail": True}
    ]
    findings, errors = ingest_scan_concert_steps(
        steps, MagicMock(), ["rkhunter", "chkrootkit", "unhide"]
    )
    assert findings == []
    assert {e.pack for e in errors} == {"rkhunter", "chkrootkit", "unhide"}
    assert all("Not authorized" in e.error for e in errors)


def test_missing_step_and_missing_report_are_errors() -> None:
    steps = [{"step": "scan-rkhunter", "pack": "rkhunter", "ok": True}]
    _, errors = ingest_scan_concert_steps(steps, MagicMock(), ["rkhunter", "lynis"])
    assert {e.pack for e in errors} == {"rkhunter", "lynis"}


def test_scan_result_with_pack_errors_is_not_clean() -> None:
    result = ScanResult(job_id="j", profile=ScanProfile.QUICK, paths=[], started_at=datetime.now())
    result.pack_errors.append(PackError(pack="rkhunter", error="Not authorized"))
    result.finalize()
    assert result.clean is False


# --- S2: clamscan exit code >= 2 ------------------------------------------------------


@pytest.mark.parametrize("rc", [2, 40, 50])
def test_clamscan_error_exit_raises_partial_with_findings(rc: int) -> None:
    pack = ClamAVPack()
    res = CommandResult(rc, f"/d/x: Eicar FOUND\n{_SUMMARY}", "LibClamAV Error: cl_load failed")
    with patch.object(pack, "scan", return_value=res):
        with pytest.raises(PartialScanError) as exc_info:
            pack.scan_paths(["/d"])
    assert "exit" in str(exc_info.value)
    assert [f.path for f in exc_info.value.findings] == ["/d/x"]


def test_clamscan_clean_exit_returns_findings() -> None:
    pack = ClamAVPack()
    with patch.object(pack, "scan", return_value=CommandResult(0, f"/d/a: OK\n{_SUMMARY}", "")):
        assert pack.scan_paths(["/d"]) == []


def test_non_utf8_output_does_not_raise() -> None:
    from oyst_core.privileged import runner

    proc = MagicMock(returncode=1, stdout="", stderr="")
    with patch.object(runner.subprocess, "run", return_value=proc) as run:
        runner.run_command(["clamscan", "-r", "/d"])
    assert run.call_args.kwargs["errors"] == "backslashreplace"


# --- S3: FOUND-line parsing -----------------------------------------------------------


def test_colon_in_filename_targets_real_malware_path() -> None:
    out = f"/home/u/Downloads/report.pdf:x.exe: Win.Trojan.X FOUND\n{_SUMMARY}"
    assert _parse(out) == [("/home/u/Downloads/report.pdf:x.exe", "Win.Trojan.X")]


def test_found_substring_in_clean_line_is_not_a_finding() -> None:
    out = f"/home/u/NOT_FOUND.txt: OK\n/home/u/FOUND: OK\n{_SUMMARY}"
    assert _parse(out) == []


def test_newline_in_filename_is_rejoined_not_split() -> None:
    # File literally named "a\n/home/u/thesis.odt" is infected; thesis.odt is not.
    out = f"/home/u/a\n/home/u/thesis.odt: Eicar FOUND\n/home/u/thesis.odt: OK\n{_SUMMARY}"
    assert _parse(out) == [("/home/u/a\n/home/u/thesis.odt", "Eicar")]


def test_summary_section_is_ignored() -> None:
    out = f"/d/a: OK\n{_SUMMARY}Weird line: something FOUND\n"
    assert _parse(out) == []
