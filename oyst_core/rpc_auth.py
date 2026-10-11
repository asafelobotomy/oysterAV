"""RPC Unix socket authentication."""

from __future__ import annotations

import contextlib
import os
import secrets
import socket
import stat
import struct
import tempfile
import time
from pathlib import Path

from oyst_core.config import data_dir
from oyst_core.rpc_errors import RpcAuthError

TOKEN_FILENAME = "oyst.token"
TOKEN_BYTES = 32
_MIN_TOKEN_LEN = 22
_MAX_TOKEN_FILE_BYTES = 4096
_READ_RETRIES = 5
_READ_RETRY_DELAY_S = 0.02


def token_path() -> Path:
    return data_dir() / TOKEN_FILENAME


def _read_token(path: Path) -> str | None:
    """Read the token without following symlinks; ``None`` when missing."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"RPC token is not a regular file: {path}")
        if st.st_uid == os.getuid() and st.st_mode & 0o777 != 0o600:
            os.fchmod(handle.fileno(), 0o600)
        raw = handle.read(_MAX_TOKEN_FILE_BYTES)
    return raw.decode("utf-8", errors="replace").strip()


def _install_token(path: Path, *, replace: bool) -> None:
    """Write a fresh token to a 0600 temp file, then link/replace it into place.

    ``os.link`` fails with ``FileExistsError`` when another process won the race,
    so readers never observe a partially written token file.
    """
    fd, tmp_name = tempfile.mkstemp(prefix=".oyst.token.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (secrets.token_urlsafe(TOKEN_BYTES) + "\n").encode())
        os.fsync(fd)
        os.close(fd)
        fd = -1
        if replace:
            os.replace(tmp_name, path)
        else:
            os.link(tmp_name, path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)


def ensure_rpc_token() -> str:
    """Create or load the RPC auth token (mode 0600, atomic create)."""
    path = token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    for _attempt in range(_READ_RETRIES):
        token = _read_token(path)
        if token is None:
            try:
                _install_token(path, replace=False)
            except FileExistsError:
                pass  # another process created it; re-read
            continue
        if len(token) >= _MIN_TOKEN_LEN:
            return token
        time.sleep(_READ_RETRY_DELAY_S)
    # Persistently short/corrupt (legacy) file: swap in a new one atomically.
    _install_token(path, replace=True)
    token = _read_token(path)
    if token is None or len(token) < _MIN_TOKEN_LEN:
        raise OSError(f"could not create RPC token at {path}")
    return token


def load_rpc_token() -> str | None:
    try:
        token = _read_token(token_path())
    except OSError:
        return None
    if token is None or len(token) < _MIN_TOKEN_LEN:
        return None
    return token


def verify_peer_credentials(conn: socket.socket) -> None:
    """Require connecting UID to match this process / data_dir owner."""
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    except OSError as exc:
        raise RpcAuthError(f"peer credentials unavailable: {exc}") from exc
    try:
        _pid, peer_uid, _gid = struct.unpack("iii", creds)
    except struct.error as exc:
        raise RpcAuthError(f"peer credentials unavailable: {exc}") from exc
    owner_uid = os.stat(token_path().parent).st_uid if token_path().parent.exists() else os.getuid()
    if peer_uid != owner_uid or peer_uid != os.getuid():
        raise RpcAuthError("RPC peer UID does not match socket owner")


def verify_rpc_token(provided: str | None) -> None:
    expected = load_rpc_token()
    if expected is None:
        expected = ensure_rpc_token()
    if not isinstance(provided, str) or not provided:
        raise RpcAuthError("invalid or missing RPC token")
    try:
        provided_bytes = provided.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates
        raise RpcAuthError("invalid or missing RPC token") from exc
    if not secrets.compare_digest(provided_bytes, expected.encode("utf-8")):
        raise RpcAuthError("invalid or missing RPC token")
