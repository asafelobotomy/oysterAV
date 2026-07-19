"""Job progress EventLog + job.status RPC."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from oyst_core.events import EventLog
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_auth import ensure_rpc_token
from oyst_core.serve import RpcServer
from oysterav.gui.rpc_actions import request_job_status


def test_job_progress_idle_and_active(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    idle = events.get_job_progress()
    assert idle["active"] is False
    assert idle["job_id"] is None

    assert events.acquire_job_lock("job-1") is True
    events.set_job_progress(
        "job-1",
        pack="clamav",
        message="Running clamav",
        percent=33.0,
        state="running",
    )
    prog = events.get_job_progress()
    assert prog["active"] is True
    assert prog["job_id"] == "job-1"
    assert prog["pack"] == "clamav"
    assert prog["percent"] == 33.0
    assert prog["state"] == "running"

    events.release_job_lock("job-1")
    assert events.get_job_progress()["active"] is False


def test_rpc_job_status() -> None:
    server = RpcServer()
    token = ensure_rpc_token()
    resp = server.handle({"method": "job.status", "params": {}, "id": 1, "auth": token})
    assert "result" in resp
    assert "active" in resp["result"]


def test_request_job_status() -> None:
    client = MagicMock()
    client.job_status.return_value = {"active": False, "percent": 0.0}
    assert request_job_status(client)["active"] is False
    client.job_status.assert_called_once_with()


def test_orchestrator_job_status_delegates(tmp_path: Path) -> None:
    events = EventLog(db_path=tmp_path / "events.db")
    orch = JobOrchestrator(events)
    assert orch.job_status()["active"] is False
    events.acquire_job_lock("j2")
    events.set_job_progress("j2", pack="maldet", message="Running", percent=50.0)
    status = orch.job_status()
    assert status["pack"] == "maldet"
    assert status["percent"] == 50.0
    events.release_job_lock("j2")
