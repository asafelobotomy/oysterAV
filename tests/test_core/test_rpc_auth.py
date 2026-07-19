"""RPC authentication tests."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from oyst_core.rpc_auth import ensure_rpc_token, verify_rpc_token
from oyst_core.rpc_errors import RpcAuthError
from oyst_core.serve import RpcServer


@pytest.fixture
def rpc_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RpcServer:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    sock = tmp_path / "test.sock"
    return RpcServer(sock)


def test_verify_rpc_token_rejects_invalid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    ensure_rpc_token()
    with pytest.raises(RpcAuthError):
        verify_rpc_token("wrong-token")


def test_rpc_handle_requires_valid_token(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    token = ensure_rpc_token()
    response = rpc_server.handle({"method": "setup.status", "params": {}, "id": 1, "auth": token})
    assert "result" in response
    bad = rpc_server.handle({"method": "setup.status", "params": {}, "id": 2, "auth": "bad"})
    assert bad.get("error", {}).get("code") == "auth_failed"


def test_rpc_rejects_invalid_profile_in_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.schedule_util import install_user_timer

    monkeypatch.setattr(
        "oyst_core.schedule_util.resolve_oyst_cli_path",
        lambda: "/usr/bin/oyst-cli",
    )
    with pytest.raises(ValueError, match="invalid scan profile"):
        install_user_timer("not-a-profile")


def test_rpc_server_socket_permissions(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    sock_path = tmp_path / "test.sock"

    def run_briefly() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        sock_path.chmod(0o600)
        server.close()

    run_briefly()
    assert sock_path.stat().st_mode & 0o777 == 0o600


def test_rpc_client_request_with_token(
    rpc_server: RpcServer,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    token = ensure_rpc_token()
    response = rpc_server.handle(
        {"method": "audit.list", "params": {"limit": 5}, "id": 3, "auth": token},
    )
    assert "result" in response
    assert isinstance(response["result"], list)
