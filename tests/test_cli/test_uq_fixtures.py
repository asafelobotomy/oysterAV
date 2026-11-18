"""tests/uq/fixtures/ are what the real `oyst-cli` commands print, as the uQ page reads them.

The page's QML and Node tests answer every command from these files, so a command that changes
its output would otherwise leave them testing a fiction. Each fixture is compared by *shape* (keys
and value types, recursively; a list by its first element) with what the command prints now.
`UPDATE_FIXTURES=1 uv run pytest tests/test_cli/test_uq_fixtures.py` rewrites them.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.events import EventLog
from oyst_core.quarantine import QuarantineVault

FIXTURES = Path(__file__).resolve().parents[1] / "uq" / "fixtures"
UPDATE = os.environ.get("UPDATE_FIXTURES") == "1"
ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?$")
WHEN = "2026-11-16T09:30:00"

# fixture file -> the oyst-cli arguments it records.
COMMANDS: dict[str, list[str]] = {
    "summary.json": ["status", "summary", "--deep", "--json"],
    "setup-status.json": ["setup", "status", "--json"],
    "preview-setup.json": ["setup", "run", "--dry-run", "--json"],
    "preview-setup-basic.json": [
        "setup",
        "run",
        "--skip-harden",
        "--no-enable-firewall",
        "--dry-run",
        "--json",
    ],
    "job.json": ["job", "status", "--json"],
    "history.json": ["history", "--limit", "20", "--json"],
    "quarantine.json": ["quarantine", "list", "--json"],
    "quarantine-verify.json": ["quarantine", "verify", "--json"],
    "schedule.json": ["schedule", "status", "--json"],
    "services.json": ["services", "status", "--json"],
    "signatures.json": ["freshclam", "status", "--json"],
    "doctor.json": ["doctor", "--json"],
    "helper.json": ["helper-status", "--json"],
    "audit.json": ["audit", "list", "--limit", "30", "--json"],
    "config.json": ["config", "show", "--json"],
    "preview-scan.json": ["scan", "{dir}", "--profile", "quick", "--dry-run", "--json"],
    "preview-rootkit.json": ["scan", "--profile", "integrity", "--dry-run", "--json"],
    "preview-restore.json": ["quarantine", "restore", "1", "--dry-run", "--json"],
    "preview-delete.json": ["quarantine", "delete", "1", "--dry-run", "--json"],
    "preview-reconcile.json": [
        "quarantine",
        "reconcile",
        "--delete-orphans",
        "--dry-run",
        "--json",
    ],
    "preview-quarantine-add.json": [
        "quarantine",
        "add",
        "{file}",
        "--threat",
        "Test.Threat",
        "--dry-run",
        "--json",
    ],
    "preview-service.json": ["services", "set", "clamd", "on", "--dry-run", "--json"],
}


@pytest.fixture
def state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home with one scan in the history, one quarantined file and an audit entry."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "scan").mkdir()
    (tmp_path / "scan" / "a.txt").write_text("a")
    bad = tmp_path / "Downloads" / "bad.exe"
    bad.parent.mkdir()
    bad.write_bytes(b"MZ-eicar")
    EventLog().save_scan(
        {
            "job_id": "job-1",
            "profile": "quick",
            "paths": [str(tmp_path / "Downloads")],
            "started_at": WHEN,
            "finished_at": WHEN,
            "clean": False,
            "state": "completed",
            "pack_errors": [],
            "findings": [
                {
                    "pack": "clamav",
                    "path": str(bad),
                    "threat_name": "Win.Test.EICAR_HDB-1",
                    "severity": "high",
                    "message": "",
                    "raw_line": "",
                    "quarantined": False,
                    "resolved": False,
                }
            ],
        }
    )
    QuarantineVault().add(str(bad), "Win.Test.EICAR_HDB-1")
    from oyst_core.audit import SecurityAudit

    SecurityAudit().log("config.set", "scan.max_files", data={"old": "10000", "new": "500"})
    return tmp_path


def shape(value: Any) -> Any:
    """Keys and types of a JSON value; a list is its first element's shape (or [])."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    return type(value).__name__ if value is not None else "null"


def compatible(want: Any, got: Any) -> bool:
    """`got` has every key `want` has, with the same types (null matches anything)."""
    if want == "null" or got == "null":
        return True
    if isinstance(want, dict):
        return isinstance(got, dict) and all(
            k in got and compatible(v, got[k]) for k, v in want.items()
        )
    if isinstance(want, list):
        return isinstance(got, list) and (not want or not got or compatible(want[0], got[0]))
    return want == got


def normalise(value: Any, home: str) -> Any:
    if isinstance(value, dict):
        return {k: normalise(v, home) for k, v in value.items()}
    if isinstance(value, list):
        return [normalise(v, home) for v in value]
    if isinstance(value, str):
        if ISO.match(value):
            return WHEN
        return re.sub(r"[0-9a-f]{64}", "0" * 64, value.replace(home, "/home/user"))
    return value


def record(state: Path, name: str) -> Any:
    args = [
        a.format(dir=state / "scan", file=state / "Downloads" / "bad.exe") for a in COMMANDS[name]
    ]
    result = CliRunner().invoke(cli, args)
    assert result.output.strip(), (name, result.exception)
    return json.loads(result.output)


@pytest.mark.parametrize("name", sorted(COMMANDS))
def test_fixture_matches_what_the_command_prints(state: Path, name: str) -> None:
    got = record(state, name)
    path = FIXTURES / name
    if UPDATE:
        data = normalise(got, str(state))
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    assert path.is_file(), f"{name} is missing: UPDATE_FIXTURES=1 uv run pytest {__file__}"
    want = json.loads(path.read_text(encoding="utf-8"))
    assert compatible(shape(want), shape(got)), (
        f"{name} is out of date; run UPDATE_FIXTURES=1 pytest {Path(__file__).name}"
    )


def test_quarantine_entry_shape_has_what_the_page_reads(state: Path) -> None:
    entry = record(state, "quarantine.json")[0]
    assert {"id", "original_path", "threat_name", "quarantined_at"} <= set(entry)
    assert datetime.fromisoformat(entry["quarantined_at"])
