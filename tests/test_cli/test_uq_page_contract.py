"""What the uQ Settings page relies on beyond plain `--json`: `config show|set`, the plan
document of `--dry-run --json`, and the streamed (`--ndjson`) scan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core import config_schema
from oyst_core.models import ExitCode, ScanProfile, ScanResult


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _run(*args: str) -> Any:
    return CliRunner().invoke(cli, list(args))


def _plan_ok(doc: dict[str, Any]) -> None:
    """The shape uQ's confirmation sheet reads."""
    assert isinstance(doc["summary"], str)
    assert isinstance(doc["would_refuse"], bool)
    assert isinstance(doc["reason"], str)
    for entry in doc["changes"]:
        assert entry["label"]
        assert set(entry) <= {"label", "group", "detail", "bytes", "reversible"}


def test_config_show_has_a_value_and_a_schema_for_every_key() -> None:
    result = _run("config", "show", "--json")
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["path"].endswith("config.toml")
    keys = [item["key"] for item in doc["schema"]]
    assert len(keys) == len(set(keys))
    assert set(keys) == set(doc["values"])
    for item in doc["schema"]:
        assert item["kind"] in {"bool", "choice", "int", "text", "list"}
        assert item["group"] and item["label"]
        if item["kind"] == "choice":
            assert doc["values"][item["key"]] in item["choices"] or doc["values"][item["key"]] == ""


def test_every_choice_in_the_schema_is_accepted_by_config_set() -> None:
    for item in config_schema.SCHEMA:
        for choice in item.get("choices", []) if item["kind"] == "choice" else []:
            result = _run("config", "set", item["key"], choice, "--dry-run", "--json")
            doc = json.loads(result.output)
            assert result.exit_code == 0 and not doc["would_refuse"], (item["key"], choice, doc)
            _plan_ok(doc)


def test_config_set_writes_and_show_reads_it_back() -> None:
    assert _run("config", "set", "scan.max_files", "500", "--json").exit_code == 0
    doc = json.loads(_run("config", "show", "--json").output)
    assert doc["values"]["scan.max_files"] == 500
    assert _run("config", "set", "scan.exclude_dirs", "~/a,/b", "--json").exit_code == 0
    doc = json.loads(_run("config", "show", "--json").output)
    assert doc["values"]["scan.exclude_dirs"] == ["~/a", "/b"]


def test_config_set_refusal_is_json_and_changes_nothing() -> None:
    result = _run("config", "set", "scan.max_files", "0", "--json")
    assert result.exit_code == int(ExitCode.ERROR)
    doc = json.loads(result.output)
    assert doc == {"ok": False, "key": "scan.max_files", "error": "scan.max_files must be >= 1"}
    shown = json.loads(_run("config", "show", "--json").output)
    assert shown["values"]["scan.max_files"] == 10000
    assert _run("config", "set", "no.such.key", "1", "--json").exit_code == int(ExitCode.ERROR)


def test_config_set_dry_run_is_a_plan_and_writes_nothing() -> None:
    result = _run("config", "set", "scan.max_files", "500", "--dry-run", "--json")
    doc = json.loads(result.output)
    assert result.exit_code == 0 and doc["ok"] and not doc["would_refuse"]
    assert doc["changes"][0]["detail"] == "10000 → 500"
    _plan_ok(doc)
    shown = json.loads(_run("config", "show", "--json").output)
    assert shown["values"]["scan.max_files"] == 10000
    bad = json.loads(_run("config", "set", "scan.max_files", "x", "--dry-run", "--json").output)
    assert bad["would_refuse"] and bad["reason"] and not bad["changes"]
    _plan_ok(bad)


def test_scan_dry_run_counts_files_and_refuses_a_missing_folder(tmp_path: Path) -> None:
    (tmp_path / "scan" / "sub").mkdir(parents=True)
    (tmp_path / "scan" / "a").write_text("x")
    (tmp_path / "scan" / "sub" / "b").write_text("y")
    doc = json.loads(
        _run("scan", str(tmp_path / "scan"), "--profile", "quick", "--dry-run", "--json").output
    )
    _plan_ok(doc)
    assert not doc["would_refuse"]
    looks = [c for c in doc["changes"] if c.get("group") == "Looks at"]
    assert looks and looks[0]["detail"] == "2 files"
    assert doc["summary"].startswith("2 files")
    assert "privileged" in doc  # the privilege plan is still there for older callers
    missing = json.loads(_run("scan", str(tmp_path / "nope"), "--dry-run", "--json").output)
    assert missing["would_refuse"] and "Not found" in missing["reason"]


def test_integrity_scan_dry_run_names_what_asks_for_a_password() -> None:
    doc = json.loads(_run("scan", "--profile", "integrity", "--dry-run", "--json").output)
    _plan_ok(doc)
    if doc["needs_elevation"]:
        assert any(c["group"] == "Needs your password" for c in doc["changes"])


def test_scan_ndjson_streams_progress_then_the_result(tmp_path: Path) -> None:
    result = ScanResult(
        job_id="j1",
        profile=ScanProfile.QUICK,
        paths=[str(tmp_path)],
        started_at=__import__("datetime").datetime.now(),
    )

    def fake_run(self: Any, **kwargs: Any) -> tuple[ScanResult, ExitCode]:
        kwargs["on_progress"]("Starting", 0.0)
        kwargs["on_progress"]("clamav", 50.0)
        return result, ExitCode.SUCCESS

    with patch("oyst_cli.commands.scan.JobOrchestrator.run_scan", fake_run):
        out = _run("scan", str(tmp_path), "--ndjson")
    assert out.exit_code == 0
    events = [json.loads(line) for line in out.output.splitlines()]
    assert [e["event"] for e in events] == ["progress", "progress", "result"]
    assert events[1] == {"event": "progress", "stage": "clamav", "percent": 50.0}
    assert events[2]["job_id"] == "j1" and events[2]["clean"] is True


def test_scan_ndjson_keeps_the_exit_code_when_threats_are_found(tmp_path: Path) -> None:
    result = ScanResult(
        job_id="j2",
        profile=ScanProfile.QUICK,
        paths=[],
        started_at=__import__("datetime").datetime.now(),
    )
    with patch(
        "oyst_cli.commands.scan.JobOrchestrator.run_scan",
        lambda self, **kw: (result, ExitCode.THREATS_FOUND),
    ):
        out = _run("scan", str(tmp_path), "--ndjson")
    assert out.exit_code == int(ExitCode.THREATS_FOUND)
    assert json.loads(out.output.splitlines()[-1])["event"] == "result"


class _Entry:
    original_path = "/home/u/Downloads/bad.exe"
    threat_name = "Win.Test.EICAR"
    vault_path = "/nonexistent/vault/1"


def test_quarantine_plans_name_the_file_and_what_cannot_be_undone() -> None:
    with patch("oyst_cli.commands.quarantine.QuarantineVault") as vault:
        vault.return_value.get.return_value = _Entry()
        restore = json.loads(_run("quarantine", "restore", "1", "--dry-run", "--json").output)
        delete = json.loads(_run("quarantine", "delete", "1", "--dry-run", "--json").output)
    _plan_ok(restore)
    _plan_ok(delete)
    assert restore["dest"] == _Entry.original_path  # the older keys stay
    assert restore["changes"][0]["label"] == "bad.exe"
    assert "bytes" not in restore["changes"][0]  # the vault file is missing: size unknown
    assert delete["changes"][0]["reversible"] is False
    vault.return_value.delete.assert_not_called()


def test_quarantine_add_dry_run_moves_nothing(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"abc")
    with patch("oyst_core.history_actions.quarantine_and_patch") as add:
        doc = json.loads(
            _run("quarantine", "add", str(target), "--threat", "T", "--dry-run", "--json").output
        )
        gone = json.loads(
            _run("quarantine", "add", str(tmp_path / "x"), "--dry-run", "--json").output
        )
    add.assert_not_called()
    _plan_ok(doc)
    assert doc["changes"][0]["bytes"] == 3
    assert gone["would_refuse"]


def test_services_set_dry_run_changes_nothing() -> None:
    with patch("oyst_cli.commands.services_cmd.set_service") as set_service:
        doc = json.loads(_run("services", "set", "clamd", "on", "--dry-run", "--json").output)
    set_service.assert_not_called()
    _plan_ok(doc)
