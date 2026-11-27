"""clamscan per-file progress: streamed output, file counting, throttled job progress."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from oyst_core.orchestrator_helpers import OrchestratorHelpersMixin
from oyst_core.packs.clamav_output import (
    count_files,
    file_counter,
    is_file_line,
    keep_line,
    parse_clamscan_stdout,
)
from oyst_core.privileged import runner_stream


def test_file_lines_and_kept_lines() -> None:
    assert is_file_line("/home/u/a.txt: OK")
    assert is_file_line("/home/u/eicar.com: Eicar-Test-Signature FOUND")
    assert not is_file_line("LibClamAV Warning: something: odd")
    assert not is_file_line("----------- SCAN SUMMARY -----------")
    assert not is_file_line("Known viruses: 3627000")
    assert not keep_line("/home/u/a.txt: OK")
    assert keep_line("/home/u/eicar.com: Eicar-Test-Signature FOUND")
    assert keep_line("ERROR: Can't open file /x")


def test_count_files_skips_excluded_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one").write_text("1")
    (tmp_path / "a" / "two").write_text("2")
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "three").write_text("3")
    (tmp_path / "link").symlink_to(tmp_path / "skip")
    assert count_files([str(tmp_path)], [str(tmp_path / "skip")]) == 2  # dir links: not followed
    assert count_files([str(tmp_path / "a" / "one")], []) == 1
    assert count_files([str(tmp_path)], [], budget_s=-1) is None


def test_file_counter_reports_each_file() -> None:
    seen: list[tuple[int, int | None]] = []
    hook = file_counter(lambda d, t: seen.append((d, t)), 2)
    for line in ("/a: OK", "LibClamAV Warning: x: y", "/b: Eicar FOUND", "Scanned files: 2"):
        hook(line)
    assert seen == [(0, 2), (1, 2), (2, 2)]


def test_streaming_keeps_only_needed_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_stream, "ALLOWED_COMMANDS", frozenset({"python3", "python"}))
    script = "print('/a: OK'); print('/b: Eicar FOUND'); import sys; print('oops', file=sys.stderr)"
    lines: list[str] = []
    res = runner_stream.run_command_streaming(
        [sys.executable, "-c", script], on_line=lines.append, keep=keep_line
    )
    assert res.returncode == 0
    assert lines == ["/a: OK", "/b: Eicar FOUND"]
    assert res.stdout == "/b: Eicar FOUND"
    assert res.stderr == "oops"
    assert [f.path for f in parse_clamscan_stdout("clamav", res.stdout)] == ["/b"]


def test_streaming_cancel_stops_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_stream, "ALLOWED_COMMANDS", frozenset({"python3", "python"}))
    res = runner_stream.run_command_streaming(
        [sys.executable, "-c", "import time; print('/a: OK', flush=True); time.sleep(60)"],
        on_line=lambda _l: None,
        keep=keep_line,
        should_cancel=lambda: True,
        poll=0.1,
        grace=2,
    )
    assert res.stopped == "cancel"


def test_pack_progress_moves_between_start_and_end() -> None:
    helper = OrchestratorHelpersMixin.__new__(OrchestratorHelpersMixin)
    emitted: list[dict[str, Any]] = []
    helper._emit_progress = lambda job_id, **kw: emitted.append(kw)  # type: ignore[method-assign]
    report = helper._pack_progress("j", "clamav", 75.0, 100.0, None, every_s=0)
    report(0, 1000)
    report(500, 1000)
    report(1000, 1000)
    assert [round(float(e["percent"]), 2) for e in emitted] == [75.0, 87.5, 99.75]
    assert emitted[1]["message"] == "Scanning with clamav: 500 of about 1,000 files"
    report(42, None)
    assert emitted[-1]["percent"] == 75.0
    assert emitted[-1]["message"] == "Scanning with clamav: 42 files so far"


def test_pack_progress_is_throttled() -> None:
    helper = OrchestratorHelpersMixin.__new__(OrchestratorHelpersMixin)
    helper._emit_progress = MagicMock()  # type: ignore[method-assign]
    report = helper._pack_progress("j", "clamav", 0.0, 100.0, None, every_s=60)
    report(0, 10)
    for n in range(1, 10):
        report(n, 10)
    assert helper._emit_progress.call_count == 1
