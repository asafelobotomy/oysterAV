"""RPC Unix socket authentication."""

from __future__ import annotations

import os
import secrets
import socket
from pathlib import Path

from oyst_core.config import data_dir
from oyst_core.rpc_errors import RpcAuthError

TOKEN_FILENAME = "oyst.token"
TOKEN_BYTES = 32


def token_path() -> Path:
    return data_dir() / TOKEN_FILENAME


def ensure_rpc_token() -> str:
    """Create or load the RPC auth token (mode 0600, atomic create)."""
    path = token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            path.chmod(0o600)
            return token
    token = secrets.token_urlsafe(TOKEN_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            path.chmod(0o600)
            return existing
        fd = os.open(str(path), os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (token + "\n").encode())
    finally:
        os.close(fd)
    path.chmod(0o600)
    return token


def load_rpc_token() -> str | None:
    path = token_path()
    if not path.is_file():
        return None
    token = path.read_text(encoding="utf-8").strip()
    return token or None


def verify_peer_credentials(conn: socket.socket) -> None:
    """Require connecting UID to match this process / data_dir owner."""
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    except OSError as exc:
        raise RpcAuthError(f"peer credentials unavailable: {exc}") from exc
    peer_uid = int.from_bytes(creds[4:8], byteorder="little", signed=True)
    owner_uid = os.stat(token_path().parent).st_uid if token_path().parent.exists() else os.getuid()
    if peer_uid != owner_uid or peer_uid != os.getuid():
        raise RpcAuthError("RPC peer UID does not match socket owner")


def verify_rpc_token(provided: str | None) -> None:
    expected = load_rpc_token()
    if expected is None:
        expected = ensure_rpc_token()
    if not provided or not secrets.compare_digest(provided, expected):
        raise RpcAuthError("invalid or missing RPC token")
