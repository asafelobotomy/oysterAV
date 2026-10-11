"""Low-severity scan history / export / event log regressions."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import pytest

from oyst_core.events import EventLog


def _scan(job_id: str = "job-1", n: int = 2, started: str = "2026-01-01T00:00:00") -> dict:
    return {
        "job_id": job_id,
        "profile": "quick",
        "paths": ["/srv"],
        "started_at": started,
        "finished_at": "2026-01-01T00:01:00",
        "clean": False,
        "findings": [
            {"pack": "clamav", "path": f"/srv/f{i}", "threat_name": "Eicar", "message": ""}
            for i in range(n)
        ],
    }


@pytest.fixture
def events(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> EventLog:
    monkeypatch.setenv("HOME", str(tmp_path))
    log = EventLog(tmp_path / "events.db")
    monkeypatch.setattr("oyst_core.history_actions.EventLog", lambda: log)
    monkeypatch.setattr("oyst_core.history_export.EventLog", lambda: log)
    return log


def test_concurrent_patches_do_not_lose_updates(events: EventLog) -> None:
    n = 8
    events.save_scan(_scan(n=n))
    errors: list[Any] = []

    def worker(i: int) -> None:
        res = events.patch_finding(
            "job-1", pack="clamav", path=f"/srv/f{i}", threat_name="Eicar", quarantined=True
        )
        if not res.get("ok"):
            errors.append(res)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    scan = events.get_scan("job-1")
    assert scan is not None
    assert all(f.get("quarantined") for f in scan["findings"])
    assert scan["clean"] is True


def test_patch_finding_fallback_ignores_message(events: EventLog) -> None:
    events.save_scan(_scan(n=1))
    res = events.patch_finding(
        "job-1", pack="clamav", path="/srv/f0", threat_name="Eicar", message="x", resolved=True
    )
    assert res["ok"] is True
    assert events.patch_finding("missing", pack="", path="", threat_name="")["ok"] is False


def test_save_scan_refuses_reused_job_id(events: EventLog) -> None:
    events.save_scan(_scan())
    # Same run re-saved (e.g. finishing / patching) is allowed.
    updated = _scan(n=1)
    events.save_scan(updated)
    assert len(events.get_scan("job-1")["findings"]) == 1  # type: ignore[index]
    with pytest.raises(ValueError, match="already exists"):
        events.save_scan(_scan(n=5, started="2026-02-02T00:00:00"))
    assert len(events.get_scan("job-1")["findings"]) == 1  # type: ignore[index]


def test_handle_open_findings_continues_after_runtime_error(
    events: EventLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core import history_actions

    events.save_scan(_scan(n=2))
    calls: list[str] = []

    def fake_quarantine(path: str, *_a: Any, **_k: Any) -> dict[str, Any]:
        calls.append(path)
        if path.endswith("f0"):
            raise RuntimeError("quarantine vault must be mode 0700")
        return {"ok": True}

    monkeypatch.setattr(history_actions, "quarantine_and_patch", fake_quarantine)
    res = history_actions.handle_open_findings("job-1", quarantine=True)
    assert calls == ["/srv/f0", "/srv/f1"]
    assert res["quarantined"] == 1
    assert res["ok"] is False
    assert any("mode 0700" in e for e in res["errors"])


def test_export_is_private_and_exclusive(events: EventLog, tmp_path: Path) -> None:
    from oyst_core.config import data_dir
    from oyst_core.history_export import export_all_scans_to_path, export_scan_to_path

    events.save_scan(_scan())
    exports = data_dir() / "exports"
    target = exports / "one.json"
    res = export_scan_to_path("job-1", target)
    assert res["ok"] is True
    assert target.stat().st_mode & 0o777 == 0o600
    assert json.loads(target.read_text(encoding="utf-8"))["job_id"] == "job-1"
    again = export_scan_to_path("job-1", target)
    assert again["ok"] is False and "overwrite" in again["error"]
    # A dangling symlink planted at the target is never followed.
    victim = tmp_path / "victim.md"
    link = exports / "all.md"
    link.symlink_to(victim)
    res = export_all_scans_to_path(exports / "all.md", fmt="md")
    assert res["ok"] is False
    assert not victim.exists()


def test_event_log_redacts_message(events: EventLog) -> None:
    events.log("scan", "finished /home/alice/secret.txt", {"p": "/home/alice/x"})
    with events._connect() as conn:
        row = conn.execute("SELECT message, data FROM events").fetchone()
    assert "alice" not in row["message"]
    assert "alice" not in row["data"]
