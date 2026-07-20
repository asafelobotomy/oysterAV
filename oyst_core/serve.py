"""JSON-RPC serve mode for GUI clients."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any

from oyst_core.config import data_dir
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_auth import ensure_rpc_token, verify_peer_credentials, verify_rpc_token
from oyst_core.rpc_errors import RpcError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_io import recv_framed

SCHEMA_VERSION = 2
DEFAULT_SOCKET = data_dir() / "oyst.sock"
_CONN_TIMEOUT_SEC = 120.0
_MAX_CONCURRENT_CONNS = 8
_logger = logging.getLogger("oyst.rpc")
_accept_semaphore = threading.BoundedSemaphore(_MAX_CONCURRENT_CONNS)


def socket_is_live(socket_path: Path) -> bool:
    if not socket_path.exists():
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            sock.connect(str(socket_path))
        return True
    except OSError:
        return False


def ensure_rpc_server(
    socket_path: Path | None = None,
    *,
    wait_seconds: float = 3.0,
) -> None:
    path = socket_path or DEFAULT_SOCKET
    if socket_is_live(path):
        return
    if path.exists():
        path.unlink()
    ensure_rpc_token()
    threading.Thread(
        target=lambda: RpcServer(path).serve_forever(),
        daemon=True,
    ).start()
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if socket_is_live(path):
            return
        time.sleep(0.05)
    msg = f"RPC server failed to start on {path}"
    raise RuntimeError(msg)


class RpcServer:
    def __init__(self, socket_path: Path | None = None) -> None:
        self.socket_path = socket_path or DEFAULT_SOCKET
        self.orchestrator = JobOrchestrator()
        self._running = False
        ensure_rpc_token()

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method", "")
        params = request.get("params") or {}
        rid = request.get("id", 0)
        auth_token = request.get("auth")
        try:
            verify_rpc_token(auth_token if isinstance(auth_token, str) else None)
            result = self._dispatch(method, params)
            return {"id": rid, "schema_version": SCHEMA_VERSION, "result": result}
        except RpcError as exc:
            return {
                "id": rid,
                "schema_version": SCHEMA_VERSION,
                "error": exc.to_dict(),
            }
        except Exception:  # noqa: BLE001 — RPC boundary
            _logger.exception("RPC error for method %s", method)
            return {
                "id": rid,
                "schema_version": SCHEMA_VERSION,
                "error": {"code": "internal_error", "message": "An internal error occurred"},
            }

    def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        return dispatch_rpc(method, params, orchestrator=self.orchestrator)

    def serve_forever(self) -> None:
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        ensure_rpc_token()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        server.listen(5)
        self._running = True
        while self._running:
            conn, _ = server.accept()
            if not _accept_semaphore.acquire(blocking=False):
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(
                target=self._handle_conn_guarded,
                args=(conn,),
                daemon=True,
            ).start()

    def _handle_conn_guarded(self, conn: socket.socket) -> None:
        try:
            self._handle_conn(conn)
        finally:
            _accept_semaphore.release()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(_CONN_TIMEOUT_SEC)
                verify_peer_credentials(conn)
            except RpcError as exc:
                response = {
                    "id": 0,
                    "schema_version": SCHEMA_VERSION,
                    "error": exc.to_dict(),
                }
                try:
                    conn.sendall((json.dumps(response) + "\n").encode())
                except OSError:
                    pass
                return
            try:
                data = recv_framed(conn).decode()
                if not data.strip():
                    return
                request = json.loads(data)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                response = {
                    "id": 0,
                    "schema_version": SCHEMA_VERSION,
                    "error": {
                        "code": "invalid_request",
                        "message": f"malformed RPC frame: {exc}",
                    },
                }
                try:
                    conn.sendall((json.dumps(response) + "\n").encode())
                except OSError:
                    pass
                return
            response = self.handle(request)
            try:
                conn.sendall((json.dumps(response) + "\n").encode())
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
