"""RPC auth hardening: token modes, compare_digest rejects, peercred UID."""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from oyst_core.rpc_auth import (
    ensure_rpc_token,
    verify_peer_credentials,
    verify_rpc_token,
)
from oyst_core.rpc_errors import RpcAuthError

pytestmark = pytest.mark.security


def test_ensure_rpc_token_mode_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    token = ensure_rpc_token()
    path = tmp_path / "oyst.token"
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert token
    # Idempotent reload keeps mode.
    ensure_rpc_token()
    assert path.stat().st_mode & 0o777 == 0o600


def test_data_dir_mode_0700(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    from oyst_core.config_io import data_dir

    d = data_dir()
    assert d.is_dir()
    assert d.stat().st_mode & 0o777 == 0o700


def test_verify_rpc_token_rejects_empty_and_truncated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    token = ensure_rpc_token()
    with pytest.raises(RpcAuthError):
        verify_rpc_token(None)
    with pytest.raises(RpcAuthError):
        verify_rpc_token("")
    with pytest.raises(RpcAuthError):
        verify_rpc_token(token[:-1])
    with pytest.raises(RpcAuthError):
        verify_rpc_token(token + "x")


def test_verify_peer_credentials_rejects_cross_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    ensure_rpc_token()
    conn = MagicMock(spec=socket.socket)
    # SO_PEERCRED: pid, uid, gid as native signed ints (struct ucred).
    other_uid = (os.getuid() + 1) % 65535
    if other_uid == os.getuid():
        other_uid = 0 if os.getuid() != 0 else 1
    creds = struct.pack("iii", 1, other_uid, 0)
    conn.getsockopt.return_value = creds
    with pytest.raises(RpcAuthError, match="UID"):
        verify_peer_credentials(conn)


def test_verify_peer_credentials_accepts_matching_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    ensure_rpc_token()
    conn = MagicMock(spec=socket.socket)
    creds = struct.pack("iii", os.getpid(), os.getuid(), os.getgid())
    conn.getsockopt.return_value = creds
    verify_peer_credentials(conn)


def test_ensure_rpc_token_regenerates_short_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    path = tmp_path / "oyst.token"
    path.write_text("short\n", encoding="utf-8")
    path.chmod(0o600)
    token = ensure_rpc_token()
    assert len(token) >= 22
    assert token != "short"
