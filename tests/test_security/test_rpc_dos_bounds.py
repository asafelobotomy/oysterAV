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
    # Reset module semaphore so prior tests cannot leak slots
    while True:
        try:
            serve_mod._accept_semaphore.release()
        except ValueError:
            break
    return tmp_path


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


def test_accept_semaphore_rejects_ninth_connection(
    rpc_tmp: Path,
) -> None:
    sock_path = rpc_tmp / "dos.sock"
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            _run_ninth_connection_rejected(sock_path)
            return
        except Exception as exc:  # noqa: BLE001 — retry flake
            last_err = exc
            try:
                sock_path.unlink(missing_ok=True)
            except OSError:
                pass
            while True:
                try:
                    serve_mod._accept_semaphore.release()
                except ValueError:
                    break
            time.sleep(0.05 * (attempt + 1))
    assert last_err is not None
    raise last_err


def _run_ninth_connection_rejected(sock_path: Path) -> None:
    server = RpcServer(sock_path)
    hold = threading.Event()
    workers_ready = threading.Barrier(serve_mod._MAX_CONCURRENT_CONNS + 1)

    def _slow_handle(_self: RpcServer, conn: socket.socket) -> None:
        try:
            workers_ready.wait(timeout=5.0)
            hold.wait(timeout=5.0)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    with patch.object(RpcServer, "_handle_conn", _slow_handle):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not sock_path.exists():
            time.sleep(0.02)
        assert sock_path.exists()

        held: list[socket.socket] = []
        try:
            for _ in range(serve_mod._MAX_CONCURRENT_CONNS):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(str(sock_path))
                held.append(s)
            workers_ready.wait(timeout=5.0)
            assert serve_mod._accept_semaphore._value == 0  # noqa: SLF001

            ninth = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            ninth.settimeout(1.0)
            ninth.connect(str(sock_path))
            try:
                data = ninth.recv(64)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                data = b""
            finally:
                ninth.close()
            assert data == b""
        finally:
            hold.set()
            for s in held:
                try:
                    s.close()
                except OSError:
                    pass
            server.stop()
            try:
                sock_path.unlink(missing_ok=True)
            except OSError:
                pass


def test_semaphore_releases_after_bad_frames(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "recycle.sock"
    server = RpcServer(sock_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not sock_path.exists():
        time.sleep(0.02)

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
    server.stop()
    assert b"result" in resp or b"error" in resp
    sock_path.unlink(missing_ok=True)


def test_non_object_json_root_rejected(rpc_tmp: Path) -> None:
    sock_path = rpc_tmp / "root.sock"
    server = RpcServer(sock_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and not sock_path.exists():
        time.sleep(0.02)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect(str(sock_path))
    s.sendall(b'["not","an","object"]\n')
    data = s.recv(4096)
    s.close()
    server.stop()
    assert b"validation_error" in data
    assert b"JSON object" in data
    sock_path.unlink(missing_ok=True)


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
