"""JSON-RPC serve mode for GUI clients."""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

from oyst_core.config import data_dir
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_auth import ensure_rpc_token, verify_peer_credentials, verify_rpc_token
from oyst_core.rpc_errors import RpcError, RpcValidationError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_io import recv_framed

SCHEMA_VERSION = 2
DEFAULT_SOCKET = data_dir() / "oyst.sock"
# Total deadline to receive one request frame (one-shot connections; long work
# runs after recv). Enforced across all recv calls, not per recv (slowloris).
_CONN_TIMEOUT_SEC = 15.0
_MAX_CONCURRENT_CONNS = 8
# Kernel backlog comfortably above the concurrency cap so over-limit clients are
# accepted and told "busy" instead of getting EAGAIN on connect.
_LISTEN_BACKLOG = 32
# accept() poll interval so stop() is honoured promptly.
_ACCEPT_POLL_SEC = 0.5
_ACCEPT_ERROR_BACKOFF_SEC = 0.1
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
    wait_seconds: float = 10.0,
    idle_exit: float | None = None,
) -> None:
    """Make sure an ``oyst-cli serve`` process is listening; spawn one if not.

    The server runs as a separate, detached process (never a thread of the
    caller), so GUI clients never host security work and jobs outlive them.
    """
    from oyst_core.serve_spawn import DEFAULT_IDLE_EXIT_SEC, serve_log_path, spawn_rpc_server

    path = socket_path or DEFAULT_SOCKET
    if socket_is_live(path):
        return
    ensure_rpc_token()
    spawn_rpc_server(path, idle_exit=DEFAULT_IDLE_EXIT_SEC if idle_exit is None else idle_exit)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if socket_is_live(path):
            return
        time.sleep(0.05)
    msg = f"oyst-cli serve failed to start on {path} (see {serve_log_path()})"
    raise RuntimeError(msg)


class RpcServer:
    def __init__(self, socket_path: Path | None = None, *, idle_exit: float = 0.0) -> None:
        self.socket_path = socket_path or DEFAULT_SOCKET
        self.orchestrator = JobOrchestrator()
        self._running = False
        self._server: socket.socket | None = None
        # Seconds without connections or an active job before exiting (0 = never).
        self.idle_exit = max(0.0, float(idle_exit))
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        self._last_activity = time.monotonic()
        ensure_rpc_token()

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method", "")
        rid = request.get("id", 0)
        auth_token = request.get("auth")
        try:
            verify_rpc_token(auth_token if isinstance(auth_token, str) else None)
            raw_params = request.get("params", {})
            if raw_params is None:
                params: dict[str, Any] = {}
            elif not isinstance(raw_params, dict):
                raise RpcValidationError("params must be an object")
            else:
                params = raw_params
            if not isinstance(method, str):
                raise RpcValidationError("method must be a string")
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

    def _bind_listener(self) -> socket.socket:
        if socket_is_live(self.socket_path):
            msg = f"RPC server already running on {self.socket_path}; refusing to replace it"
            raise RuntimeError(msg)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Create the socket node as 0600 (avoid brief umask-open window after bind).
        old_umask = os.umask(0o177)
        try:
            server.bind(str(self.socket_path))
        finally:
            os.umask(old_umask)
        self.socket_path.chmod(0o600)
        server.listen(_LISTEN_BACKLOG)
        server.settimeout(_ACCEPT_POLL_SEC)
        return server

    def serve_forever(self) -> None:
        ensure_rpc_token()
        server = self._bind_listener()
        bound_ino = self.socket_path.stat().st_ino
        self._server = server
        self._running = True
        try:
            while self._running:
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    if self._idle_expired():
                        _logger.info("RPC server idle for %.0fs; exiting", self.idle_exit)
                        break
                    continue
                except OSError as exc:
                    if not self._running:
                        break
                    # EMFILE/ENFILE/EINTR/ECONNABORTED: keep serving.
                    _logger.warning("RPC accept failed: %s", exc)
                    time.sleep(_ACCEPT_ERROR_BACKOFF_SEC)
                    continue
                if not _accept_semaphore.acquire(blocking=False):
                    self._reject_busy(conn)
                    continue
                try:
                    threading.Thread(
                        target=self._handle_conn_guarded,
                        args=(conn,),
                        daemon=True,
                    ).start()
                except RuntimeError:
                    _accept_semaphore.release()
                    conn.close()
        finally:
            self._running = False
            self._server = None
            server.close()
            try:
                if self.socket_path.stat().st_ino == bound_ino:
                    self.socket_path.unlink()
            except OSError:
                pass

    def _reject_busy(self, conn: socket.socket) -> None:
        with conn:
            self._send_error(conn, code="busy", message="RPC server busy; retry shortly")

    def _handle_conn_guarded(self, conn: socket.socket) -> None:
        with self._inflight_lock:
            self._inflight += 1
            self._last_activity = time.monotonic()
        try:
            self._handle_conn(conn)
        finally:
            with self._inflight_lock:
                self._inflight -= 1
                self._last_activity = time.monotonic()
            _accept_semaphore.release()

    def _idle_expired(self) -> bool:
        if not self.idle_exit:
            return False
        with self._inflight_lock:
            if self._inflight or time.monotonic() - self._last_activity < self.idle_exit:
                return False
        try:
            if self.orchestrator.events.active_job():
                self._last_activity = time.monotonic()
                return False
        except Exception:  # noqa: BLE001 — unknown job state: keep serving
            return False
        return True

    def _send_error(self, conn: socket.socket, *, code: str, message: str, rid: Any = 0) -> None:
        response = {
            "id": rid,
            "schema_version": SCHEMA_VERSION,
            "error": {"code": code, "message": message},
        }
        try:
            conn.settimeout(_CONN_TIMEOUT_SEC)
            conn.sendall((json.dumps(response) + "\n").encode())
        except OSError:
            pass

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(_CONN_TIMEOUT_SEC)
                verify_peer_credentials(conn)
            except RpcError as exc:
                self._send_error(conn, code=exc.code, message=exc.message)
                return
            try:
                data = recv_framed(conn, deadline_sec=_CONN_TIMEOUT_SEC).decode()
                if not data.strip():
                    return
                request = json.loads(data)
            # ValueError covers JSONDecodeError/UnicodeDecodeError; RecursionError
            # comes from deeply nested arrays/objects.
            except (OSError, ValueError, RecursionError) as exc:
                _logger.debug("malformed RPC frame: %s", exc)
                self._send_error(
                    conn,
                    code="invalid_request",
                    message="malformed RPC frame",
                )
                return
            if not isinstance(request, dict):
                self._send_error(
                    conn,
                    code="validation_error",
                    message="request must be a JSON object",
                )
                return
            response = self.handle(request)
            try:
                conn.settimeout(_CONN_TIMEOUT_SEC)
                conn.sendall((json.dumps(response) + "\n").encode())
            except OSError:
                pass

    def stop(self) -> None:
        """Stop accepting; wakes a blocked accept() by shutting the listener down."""
        self._running = False
        server = self._server
        if server is not None:
            try:
                server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
