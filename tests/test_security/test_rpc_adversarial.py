"""Adversarial corpora for RPC serve / auth / framing / dispatch."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from oyst_core.rpc_auth import ensure_rpc_token, verify_peer_credentials
from oyst_core.rpc_errors import RpcAuthError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_io import recv_framed
from oyst_core.serve import RpcServer
from tests.test_security.corpora import (
    RPC_AUTH_CASES,
    RPC_METHOD_CASES,
    RPC_PARAMS_CASES,
    Case,
)

pytestmark = pytest.mark.security


@pytest.fixture
def rpc_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RpcServer:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    return RpcServer(tmp_path / "test.sock")


def _auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    return ensure_rpc_token()


def _assert_error_kind(response: dict, case: Case) -> None:
    code = response.get("error", {}).get("code")
    kind = case.expect.kind
    if kind == "auth_error":
        assert code == "auth_failed"
    elif kind == "validation_error":
        assert code == "validation_error"
        if case.expect.substr:
            assert case.expect.substr in response["error"].get("message", "").lower()
    elif kind == "not_found":
        assert code in {"not_found", "validation_error"}
    else:
        raise AssertionError(f"unexpected expect kind {kind}")
    assert "result" not in response
    assert code != "internal_error"


@pytest.mark.parametrize("case", RPC_AUTH_CASES, ids=lambda c: c.id)
def test_handle_rejects_bad_auth(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: Case,
) -> None:
    _auth(tmp_path, monkeypatch)
    response = rpc_server.handle(
        {"method": "setup.status", "params": {}, "id": 1, "auth": case.payload},
    )
    _assert_error_kind(response, case)


def test_handle_rejects_truncated_token(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _auth(tmp_path, monkeypatch)
    response = rpc_server.handle(
        {"method": "setup.status", "params": {}, "id": 2, "auth": token[:-3]},
    )
    assert response["error"]["code"] == "auth_failed"


@pytest.mark.parametrize("case", RPC_PARAMS_CASES, ids=lambda c: c.id)
def test_handle_rejects_non_object_params(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: Case,
) -> None:
    token = _auth(tmp_path, monkeypatch)
    response = rpc_server.handle(
        {"method": "setup.status", "params": case.payload, "id": 3, "auth": token},
    )
    _assert_error_kind(response, case)


def test_handle_accepts_null_params_as_empty(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _auth(tmp_path, monkeypatch)
    response = rpc_server.handle(
        {"method": "setup.status", "params": None, "id": 4, "auth": token},
    )
    assert "result" in response


@pytest.mark.parametrize("case", RPC_METHOD_CASES, ids=lambda c: c.id)
def test_handle_method_cases(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: Case,
) -> None:
    token = _auth(tmp_path, monkeypatch)
    response = rpc_server.handle(
        {"method": case.payload, "params": {}, "id": 5, "auth": token},
    )
    _assert_error_kind(response, case)


def test_recv_framed_oversize() -> None:
    conn = MagicMock(spec=socket.socket)
    big = b"a" * (64 * 1024)
    calls = [big] * 300  # ~19MiB

    def _recv(_n: int) -> bytes:
        if not calls:
            return b""
        return calls.pop(0)

    conn.recv.side_effect = _recv
    with pytest.raises(OSError, match="maximum size"):
        recv_framed(conn, max_bytes=16 * 1024 * 1024)


def test_recv_framed_empty_and_no_newline() -> None:
    conn = MagicMock(spec=socket.socket)
    conn.recv.side_effect = [b"no-newline-then-close", b""]
    data = recv_framed(conn)
    assert data == b"no-newline-then-close"


def test_recv_framed_stops_at_newline() -> None:
    conn = MagicMock(spec=socket.socket)
    conn.recv.side_effect = [b'{"a":1}\n', b"ignored"]
    assert recv_framed(conn) == b'{"a":1}\n'


def test_dispatch_unknown_method() -> None:
    from oyst_core.rpc_errors import RpcNotFoundError

    with pytest.raises(RpcNotFoundError):
        dispatch_rpc("totally.missing", {}, orchestrator=MagicMock())


def test_peercred_rejects_cross_uid_via_rpc_auth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import struct

    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    ensure_rpc_token()
    conn = MagicMock(spec=socket.socket)
    other = (os.getuid() + 7) % 60000
    if other == os.getuid():
        other = 1 if os.getuid() != 1 else 2
    conn.getsockopt.return_value = struct.pack("iii", 1, other, 0)
    with pytest.raises(RpcAuthError):
        verify_peer_credentials(conn)
