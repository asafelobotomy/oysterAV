"""Newline-framed JSON-RPC socket I/O helpers."""

from __future__ import annotations

import socket

# Methods that may run for a long time (scans, installs, bootstrap).
LONG_RPC_METHODS = frozenset(
    {
        "job.start",
        "job.cancel",
        "rkhunter.scan",
        "rkhunter.update",
        "rkhunter.propupd",
        "rkhunter.resolve",
        "history.handle_open",
        "setup.run",
        "pack.install",
        "runtime.install",
        "runtime.remove",
        "runtime.bootstrap",
        "runtime.update",
        "maintenance.bootstrap",
        "maintenance.post_update",
        "updates.apply",
        "schedule.run",
        "clamav.clamd.ensure",
        "services.set",
        "helper.install",
        "auth.grant_service_lifecycle",
        "auth.revoke_service_lifecycle",
        "lynis.audit",
    }
)

DEFAULT_TIMEOUT_SEC = 30.0
LONG_TIMEOUT_SEC = 7200.0
_RECV_CHUNK = 65536


def timeout_for_method(method: str) -> float:
    if method in LONG_RPC_METHODS:
        return LONG_TIMEOUT_SEC
    return DEFAULT_TIMEOUT_SEC


def recv_framed(conn: socket.socket, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    """Read until newline (JSON-RPC frame delimiter) or connection close."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = conn.recv(_RECV_CHUNK)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise OSError("RPC frame exceeds maximum size")
        if b"\n" in chunk:
            break
    return b"".join(chunks)
