"""RPC DoS / resource bounds: frame size, accept semaphore, one-shot connection."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core import serve as serve_mod
from oyst_core.rpc_auth import ensure_rpc_token
from oyst_core.rpc_io import recv_framed
from oyst_core.serve import RpcServer

pytestmark = pytest.mark.security


@pytest.fixture
def rpc_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    ensure_rpc_token()
    _wait_slots_free()
    return tmp_path


def _wait_slots_free(timeout: float = 5.0) -> None:
    """Wait for handler threads from earlier tests to release their slots (no refill)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if serve_mod._accept_semaphore._value == serve_mod._MAX_CONCURRENT_CONNS:  # noqa: SLF001
            return
        time.sleep(0.01)
    raise AssertionError("RPC accept semaphore slots leaked by a previous test")


def _start(server: RpcServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and server._server is None:  # noqa: SLF001
        time.sleep(0.01)
    assert server._server is not None  # noqa: SLF001
    return thread


def _stop(server: RpcServer, thread: threading.Thread) -> None:
    server.stop()
    thread.join(timeout=5.0)
    assert not thread.is_alive()


def test_recv_framed_enforces_16mib_cap() -> None:
    conn = MagicMock(spec=socket.socket)
    chunk = b"x" * (1024 * 1024)
    remaining = [chunk] * 20  # 20 MiB without newline

    def _recv(_n: int) -> bytes:
        if not remaining:
            return b""
        return remaining.pop(0)

    conn.recv.side_effect = _recv
    with pytest.raises(OSError, match="maximum size"):
        recv_framed(conn, max_bytes=16 * 1024 * 1024)


def test_serve_is_one_request_per_connection() -> None:
    """Document one-shot design: no multi-request loop in _handle_conn."""
    import inspect

    src = inspect.getsource(RpcServer._handle_conn)
    assert src.count("recv_framed") == 1
    assert "while True" not in src


def test_accept_semaphore_rejects_ninth_connection(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "dos.sock"
    server = RpcServer(sock_path)
    hold = threading.Event()
    workers_ready = threading.Barrier(serve_mod._MAX_CONCURRENT_CONNS + 1)

    def _slow_handle(_self: RpcServer, conn: socket.socket) -> None:
        with conn:
            workers_ready.wait(timeout=5.0)
            hold.wait(timeout=5.0)

    held: list[socket.socket] = []
    with patch.object(RpcServer, "_handle_conn", _slow_handle):
        thread = _start(server)
        try:
            for _ in range(serve_mod._MAX_CONCURRENT_CONNS):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(str(sock_path))
                held.append(s)
            workers_ready.wait(timeout=5.0)
            assert serve_mod._accept_semaphore._value == 0  # noqa: SLF001

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ninth:
                ninth.settimeout(2.0)
                ninth.connect(str(sock_path))
                data = recv_framed(ninth)
            resp = json.loads(data)
            assert resp["error"]["code"] == "busy"
        finally:
            hold.set()
            for s in held:
                s.close()
            _stop(server, thread)
    _wait_slots_free()
    assert not sock_path.exists()


def test_stop_unblocks_accept_and_cleans_socket(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "stop.sock"
    server = RpcServer(sock_path)
    thread = _start(server)
    assert sock_path.exists()
    _stop(server, thread)
    assert not sock_path.exists()


def test_serve_forever_refuses_live_socket(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "live.sock"
    first = RpcServer(sock_path)
    thread = _start(first)
    try:
        with pytest.raises(RuntimeError, match="already running"):
            RpcServer(sock_path).serve_forever()
        assert sock_path.exists()
    finally:
        _stop(first, thread)


def test_accept_oserror_does_not_kill_server(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "emfile.sock"
    server = RpcServer(sock_path)
    real_accept = socket.socket.accept
    calls = {"n": 0}

    def _flaky_accept(self: socket.socket) -> tuple[socket.socket, object]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(24, "Too many open files")
        return real_accept(self)

    with patch.object(socket.socket, "accept", _flaky_accept):
        thread = _start(server)
        try:
            time.sleep(0.2)
            assert thread.is_alive()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect(str(sock_path))
                s.sendall(b"[1]\n")
                assert b"validation_error" in recv_framed(s)
        finally:
            _stop(server, thread)


def test_slowloris_frame_hits_total_deadline(
    rpc_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(serve_mod, "_CONN_TIMEOUT_SEC", 0.6)
    sock_path = rpc_tmp / "slow.sock"
    server = RpcServer(sock_path)
    thread = _start(server)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(str(sock_path))
            stop = threading.Event()

            def _trickle() -> None:
                # One byte every 0.2s: each recv is well under any per-recv timeout.
                while not stop.wait(0.2):
                    try:
                        s.sendall(b"{")
                    except OSError:
                        return

            trickler = threading.Thread(target=_trickle, daemon=True)
            start = time.monotonic()
            trickler.start()
            try:
                got = s.recv(4096)
            finally:
                stop.set()
                trickler.join(timeout=2.0)
            assert b"malformed RPC frame" in got
            assert time.monotonic() - start < 3.0
    finally:
        _stop(server, thread)


def test_deeply_nested_frame_is_malformed_not_crash(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "deep.sock"
    server = RpcServer(sock_path)
    thread = _start(server)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(str(sock_path))
            s.sendall(b"[" * 200_000 + b"\n")
            assert b"malformed RPC frame" in recv_framed(s)
    finally:
        _stop(server, thread)


def test_semaphore_releases_after_bad_frames(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "recycle.sock"
    server = RpcServer(sock_path)
    thread = _start(server)

    # Peercred will pass (same UID). Send garbage frames repeatedly.
    for _ in range(12):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(str(sock_path))
        s.sendall(b"{not-json\n")
        try:
            data = s.recv(4096)
            assert b"malformed RPC frame" in data
            assert b"JSONDecodeError" not in data
            assert b"Expecting" not in data
        except OSError:
            pass
        s.close()

    # After overflow risk, a normal request shape must still be accepted
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(str(sock_path))
    token = ensure_rpc_token()
    req = json.dumps(
        {"method": "setup.status", "params": {}, "id": 1, "auth": token},
    )
    s.sendall((req + "\n").encode())
    resp = s.recv(65536)
    s.close()
    _stop(server, thread)
    assert b"result" in resp or b"error" in resp


def test_non_object_json_root_rejected(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "root.sock"
    server = RpcServer(sock_path)
    thread = _start(server)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(str(sock_path))
    s.sendall(b'["not","an","object"]\n')
    data = s.recv(4096)
    s.close()
    _stop(server, thread)
    assert b"validation_error" in data
    assert b"JSON object" in data


def test_handle_pathological_json_params_under_frame_cap(
    rpc_tmp: Path,
) -> None:
    server = RpcServer(rpc_tmp / "patho.sock")
    token = ensure_rpc_token()
    # Huge but under 16 MiB when framed; params not an object → validation_error
    big_list = ["x"] * 50_000
    response = server.handle(
        {
            "method": "setup.status",
            "params": big_list,
            "id": 9,
            "auth": token,
        },
    )
    assert response["error"]["code"] == "validation_error"


def test_handle_deeply_nested_params_object(
    rpc_tmp: Path,
) -> None:
    server = RpcServer(rpc_tmp / "nest.sock")
    token = ensure_rpc_token()
    nested: dict = {}
    cur = nested
    for _ in range(200):
        cur["a"] = {}
        cur = cur["a"]
    response = server.handle(
        {"method": "setup.status", "params": nested, "id": 10, "auth": token},
    )
    # Nested empty object is still a dict — may succeed or fail handler; never internal
    err = response.get("error")
    if err:
        assert err["code"] != "internal_error"
    else:
        assert "result" in response
