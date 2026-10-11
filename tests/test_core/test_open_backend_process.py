"""GUI backend runs as a separate `oyst-cli serve` process; progress flows over RPC."""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core import rpc_progress
from oyst_core.client import OystClient
from oyst_core.serve import RpcServer, ensure_rpc_server, socket_is_live
from oyst_core.serve_spawn import serve_argv


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # data_dir() is ~/.local/share/oysterav; HOME isolates this process and children.
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _peer_pid(sock_path: Path) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(str(sock_path))
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, _uid, _gid = struct.unpack("3i", creds)
    return int(pid)


def _wait(predicate: object, timeout: float, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():  # type: ignore[operator]
            return True
        time.sleep(interval)
    return False


def test_serve_argv_is_isolated_and_pins_oyst_core(tmp_path: Path) -> None:
    argv = serve_argv(tmp_path / "s.sock", idle_exit=5)
    assert argv[1] == "-I"
    assert "sys.path.insert(0, " in argv[3]
    assert "'serve', '--socket'" in argv[3] and "'--idle-exit', '5'" in argv[3]


def test_ensure_rpc_server_spawns_separate_process_that_idles_out(home: Path) -> None:
    sock_path = home / "gui.sock"
    ensure_rpc_server(sock_path, wait_seconds=20.0, idle_exit=1.0)
    assert socket_is_live(sock_path)
    pid = _peer_pid(sock_path)
    assert pid != os.getpid()  # not a thread of the caller

    client = OystClient(sock_path, local_fallback=False)
    token = "a" * 32
    assert client._as_dict("progress.get", {"token": token})["seq"] == 0  # noqa: SLF001
    assert (home / ".local" / "share" / "oysterav" / "serve.log").stat().st_mode & 0o077 == 0

    # Probes count as activity, so poll slower than the idle timeout.
    try:
        assert _wait(lambda: not socket_is_live(sock_path), timeout=20.0, interval=2.5), (
            "server did not idle-exit"
        )
    finally:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass


def test_gui_client_never_dispatches_in_process(tmp_path: Path) -> None:
    client = OystClient(tmp_path / "missing.sock", local_fallback=False)
    with patch("oyst_core.client.dispatch_rpc") as dispatch:
        with pytest.raises(RuntimeError, match="not reachable"):
            client._call("status")  # noqa: SLF001
    dispatch.assert_not_called()


def test_gui_client_reports_autostart_failure(tmp_path: Path) -> None:
    client = OystClient(tmp_path / "missing.sock", local_fallback=False, autostart=True)
    with (
        patch("oyst_core.serve.ensure_rpc_server", side_effect=RuntimeError("boom")),
        patch("oyst_core.client.dispatch_rpc") as dispatch,
    ):
        with pytest.raises(RuntimeError, match="could not start oyst-cli serve: boom"):
            client._call("status")  # noqa: SLF001
    dispatch.assert_not_called()


@pytest.fixture
def live_server(home: Path) -> object:
    server = RpcServer(home / "rpc.sock")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert _wait(lambda: socket_is_live(server.socket_path), timeout=5.0)
    yield server
    server.stop()
    thread.join(timeout=5.0)


def test_progress_streams_over_rpc(live_server: RpcServer) -> None:
    def fake_install(name: str, *, on_progress: object = None) -> dict[str, object]:
        for stage, pct in (("download", 10), ("verify", 60), ("extract", 100)):
            on_progress(stage, pct)  # type: ignore[operator]
            time.sleep(0.4)
        return {"ok": True, "pack": name}

    seen: list[tuple[str, int]] = []
    client = OystClient(live_server.socket_path, local_fallback=False)
    with patch("oyst_core.runtime.bootstrap.install_pack_runtime", fake_install):
        result = client.runtime_install("rkhunter", on_progress=lambda s, p: seen.append((s, p)))
    assert result == {"ok": True, "pack": "rkhunter"}
    assert [s for s, _ in seen][:3] == ["download", "verify", "extract"]
    assert seen[-1] == ("extract", 100)


def test_progress_get_rejects_bad_token(live_server: RpcServer) -> None:
    client = OystClient(live_server.socket_path, local_fallback=False)
    with pytest.raises(RuntimeError, match="invalid progress token"):
        client._as_dict("progress.get", {"token": "../../etc"})  # noqa: SLF001


def test_progress_state_is_bounded() -> None:
    for i in range(200):
        rpc_progress.update(f"{i:032x}", "s", 1)
    assert len(rpc_progress._state) <= 64  # noqa: SLF001


def test_idle_exit_waits_for_active_job(home: Path) -> None:
    server = RpcServer(home / "idle.sock", idle_exit=0.3)
    active = {"job": "j1"}
    with patch.object(server.orchestrator.events, "active_job", lambda: active["job"]):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        assert _wait(lambda: socket_is_live(server.socket_path), timeout=5.0)
        time.sleep(1.2)
        assert thread.is_alive(), "exited while a job was active"
        active["job"] = None
        thread.join(timeout=5.0)
    assert not thread.is_alive()
    assert not server.socket_path.exists()
