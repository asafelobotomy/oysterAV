"""Tests for persistent session transcript (Settings Terminal)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from oyst_core import terminal_log
from oyst_core.rpc_handlers import data as data_handlers
from oyst_core.rpc_handlers import dispatch_rpc
from oysterav.gui.rpc_actions import (
    request_terminal_clear,
    request_terminal_export,
    request_terminal_list,
)


@pytest.fixture(autouse=True)
def _terminal_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(terminal_log, "transcript_path", lambda: tmp_path / "terminal.jsonl")
    monkeypatch.setattr(terminal_log, "data_dir", lambda: tmp_path)
    # history-style export target uses data_dir from config — patch terminal_log's import path
    monkeypatch.setattr("oyst_core.config.data_dir", lambda: tmp_path)
    terminal_log.reset_id_state_for_tests()
    return tmp_path


def test_append_list_clear_and_redact(_terminal_tmp: Path) -> None:
    terminal_log.log_structured(
        "cli",
        "scan.start",
        "started /home/alice/Downloads",
        {"path": "/home/alice/Downloads"},
    )
    terminal_log.log_raw("cli", "emit", "full /home/alice/secret")
    rows = terminal_log.list_entries(limit=10)
    assert len(rows) == 2
    assert rows[0]["layer"] == "structured"
    assert "/home/<redacted>" in rows[0]["message"]
    assert rows[0]["data"]["path"] == "/home/<redacted>/Downloads"
    assert rows[1]["layer"] == "raw"
    structured_only = terminal_log.list_entries(limit=10, layers=["structured"])
    assert len(structured_only) == 1
    assert terminal_log.clear()["ok"] is True
    assert terminal_log.list_entries() == []


def test_since_id_and_export(_terminal_tmp: Path) -> None:
    for i in range(3):
        terminal_log.log_structured("core", "step", f"step {i}")
    all_rows = terminal_log.list_entries(limit=10)
    mid = int(all_rows[0]["id"])
    newer = terminal_log.list_entries(limit=10, since_id=mid)
    assert len(newer) == 2
    out = _terminal_tmp / "exports" / "t.txt"
    result = terminal_log.export(out, fmt="txt")
    assert result["ok"] is True
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "step 0" in text
    out2 = _terminal_tmp / "exports" / "t.jsonl"
    result2 = terminal_log.export(out2, fmt="jsonl")
    assert result2["ok"] is True
    assert out2.read_text(encoding="utf-8").count("\n") == 3


def test_ring_trim(_terminal_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(terminal_log, "MAX_BYTES", 800)
    for i in range(40):
        terminal_log.log_structured("cli", "bulk", f"line-{i}-" + ("x" * 40))
    path = terminal_log.transcript_path()
    assert path.stat().st_size <= 800 + 200  # trim target with some slack for last write
    rows = terminal_log.list_entries(limit=1000)
    assert rows
    assert all("line-" in r["message"] for r in rows)


def test_rpc_skip_and_capture(_terminal_tmp: Path) -> None:
    terminal_log.log_rpc_call("job.status", {}, ok=True, result={"state": "running"})
    assert terminal_log.list_entries() == []
    terminal_log.log_rpc_call(
        "updates.apply",
        {"auth": "secret-token", "path": "/home/bob/x"},
        ok=True,
        result={"ok": True},
    )
    rows = terminal_log.list_entries(limit=10, layers=None)
    assert len(rows) == 2
    raw = [r for r in rows if r["layer"] == "raw"][0]
    assert raw["data"]["params"]["auth"] == "<redacted>"
    assert "/home/<redacted>" in str(raw["data"]["params"]["path"])


def test_handlers_and_dispatch(_terminal_tmp: Path) -> None:
    terminal_log.log_structured("cli", "x", "hello")
    listed = data_handlers.handle_terminal_list({"limit": 10}, MagicMock())
    assert listed and listed[0]["message"] == "hello"
    cleared = data_handlers.handle_terminal_clear({"confirm": True}, MagicMock())
    assert cleared["ok"] is True
    # dispatch skips logging for terminal.list
    before = len(terminal_log.list_entries(limit=100, layers=None) or [])
    dispatch_rpc("terminal.list", {"limit": 5})
    after = terminal_log.list_entries(limit=100, layers=None)
    # only the list call itself should not add; may still be empty after clear
    assert len(after) == before


def test_request_terminal_rpc_actions() -> None:
    client = MagicMock()
    client.terminal_list.return_value = [{"id": 1}]
    client.terminal_clear.return_value = {"ok": True}
    client.terminal_export.return_value = {"ok": True, "path": "/tmp/x"}
    assert request_terminal_list(client, limit=9, since_id=1, all_layers=True) == [{"id": 1}]
    client.terminal_list.assert_called_once_with(
        limit=9,
        since_id=1,
        layers=None,
        all_layers=True,
    )
    assert request_terminal_clear(client)["ok"] is True
    assert request_terminal_export(client, "/x", fmt="jsonl")["ok"] is True
    client.terminal_export.assert_called_once_with("/x", fmt="jsonl")
