"""Regression: job lock acquire/release/heartbeat races (AUDIT medium)."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from pathlib import Path

from oyst_core.events import EventLog


def _set(events: EventLog, **cols: str) -> None:
    sets = ", ".join(f"{k} = ?" for k in cols)
    with events._connect() as conn:
        conn.execute(f"UPDATE job_lock SET {sets} WHERE id = 1", tuple(cols.values()))


def test_concurrent_acquire_only_one_wins(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    EventLog(db_path=db)
    barrier = threading.Barrier(8)
    wins: list[str] = []

    def _go(i: int) -> None:
        ev = EventLog(db_path=db)
        barrier.wait()
        if ev.acquire_job_lock(f"job-{i}"):
            wins.append(f"job-{i}")

    threads = [threading.Thread(target=_go, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1
    assert EventLog(db_path=db).active_job() == wins[0]


def test_acquire_does_not_reset_cancel_when_lock_held(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    assert events.acquire_job_lock("a")
    assert events.request_cancel("a")
    assert not events.acquire_job_lock("b")
    assert events.cancel_requested()


def test_release_by_non_owner_keeps_cancel_flag(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    assert events.acquire_job_lock("owner")
    assert events.request_cancel("owner")
    events.release_job_lock("someone-else")
    assert events.active_job() == "owner"
    assert events.cancel_requested()


def test_long_running_job_with_fresh_heartbeat_not_stale(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    assert events.acquire_job_lock("long")
    _set(events, started_at=(datetime.now() - timedelta(hours=3)).isoformat())
    events.set_job_progress("long", pack="clamav", message="Running", percent=10)
    assert events.active_job() == "long"
    assert events.touch_job_heartbeat("long")
    assert not events.touch_job_heartbeat("other")


def test_missing_heartbeat_clears_lock(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    assert events.acquire_job_lock("dead")
    _set(events, heartbeat_at=(datetime.now() - timedelta(minutes=11)).isoformat())
    assert events.clear_stale_job_lock() == "dead"
    assert events.active_job() is None
    assert events.acquire_job_lock("next")


def test_heartbeat_thread_refreshes_lock(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from oyst_core import orchestrator_helpers as oh
    from oyst_core.orchestrator import JobOrchestrator

    monkeypatch.setattr(oh, "JOB_HEARTBEAT_INTERVAL_SEC", 0.02)
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events=events)
    assert events.acquire_job_lock("hb")
    old = (datetime.now() - timedelta(minutes=30)).isoformat()
    orch._ensure_job_heartbeat("hb")
    _set(events, heartbeat_at=old)
    deadline = datetime.now() + timedelta(seconds=3)
    while datetime.now() < deadline:
        with events._connect() as conn:
            beat = conn.execute("SELECT heartbeat_at FROM job_lock").fetchone()[0]
        if beat != old:
            break
    assert beat != old
    events.release_job_lock("hb")
