"""OystClient — JSON-RPC client for oyst-cli serve."""

from __future__ import annotations

import json
import socket
import threading
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from oyst_core.client_api import OystClientApi
from oyst_core.config import data_dir, load_config
from oyst_core.rpc_auth import ensure_rpc_token, load_rpc_token
from oyst_core.rpc_errors import RpcError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_io import recv_framed, timeout_for_method

if TYPE_CHECKING:
    from oyst_core.orchestrator import JobOrchestrator

DEFAULT_SOCKET = data_dir() / "oyst.sock"
_PROGRESS_POLL_SEC = 0.25


class OystClient(OystClientApi):
    """JSON-RPC client.

    ``local_fallback`` (CLI/tests default) dispatches in-process when no server is
    reachable. GUI clients pass ``local_fallback=False, autostart=True``: they
    spawn a separate ``oyst-cli serve`` process and never run security work
    in-process (ADR-002).
    """

    def __init__(
        self,
        socket_path: Path | None = None,
        *,
        local_fallback: bool = True,
        autostart: bool = False,
    ) -> None:
        self.socket_path = socket_path or DEFAULT_SOCKET
        self.local_fallback = local_fallback
        self.autostart = autostart
        self._orchestrator_obj: JobOrchestrator | None = None

    @property
    def _orchestrator(self) -> JobOrchestrator:
        if self._orchestrator_obj is None:
            from oyst_core.orchestrator import JobOrchestrator

            self._orchestrator_obj = JobOrchestrator()
        return self._orchestrator_obj

    def _auth_token(self) -> str | None:
        return load_rpc_token() or ensure_rpc_token()

    def _connect(self, method: str) -> socket.socket | None:
        if not self.socket_path.exists():
            return None
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout_for_method(method))
            sock.connect(str(self.socket_path))
        except OSError:
            sock.close()
            return None
        return sock

    def _unreachable(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self.local_fallback:
            return self._local_fallback(method, params)
        raise RuntimeError(
            f"oysterAV backend (oyst-cli serve) is not reachable at {self.socket_path}",
        )

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        sock = self._connect(method)
        if sock is None and self.autostart:
            from oyst_core.serve import ensure_rpc_server

            try:
                ensure_rpc_server(self.socket_path)
            except (OSError, RuntimeError) as exc:
                if not self.local_fallback:
                    raise RuntimeError(f"could not start oyst-cli serve: {exc}") from exc
            sock = self._connect(method)
        if sock is None:
            return self._unreachable(method, params)
        payload = (
            json.dumps(
                {
                    "method": method,
                    "params": params,
                    "id": 1,
                    "auth": self._auth_token(),
                },
            )
            + "\n"
        )
        try:
            with sock:
                sock.sendall(payload.encode())
                data = recv_framed(sock).decode()
            if not data.strip():
                raise RuntimeError("empty RPC response")
            return json.loads(data)  # type: ignore[no-any-return]
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            # Never re-dispatch after send — server may already be executing.
            raise RuntimeError(f"RPC failed after send ({method}): {exc}") from exc

    def _local_fallback(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        # Same-UID in-process path (ASVS partial): no token/peercred. Prefer serve socket.
        try:
            from oyst_core.audit import SecurityAudit

            SecurityAudit().log(
                "rpc.local_fallback",
                method,
                success=True,
                data={"reason": "socket unavailable; same-process dispatch"},
            )
        except Exception:  # noqa: BLE001 — never fail the call on audit
            pass
        try:
            return {
                "result": dispatch_rpc(
                    method,
                    params,
                    orchestrator=self._orchestrator,
                ),
            }
        except RpcError as exc:
            return {"error": exc.to_dict()}

    def _result(self, response: dict[str, Any]) -> Any:
        if "error" in response:
            err = response["error"]
            if isinstance(err, dict):
                raise RuntimeError(str(err.get("message", err)))
            raise RuntimeError(str(err))
        return response.get("result")

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        return self._result(self._request(method, params))

    def _as_dict(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self._call(method, params)
        return dict(result) if isinstance(result, dict) else {}

    def _as_list(self, method: str, params: dict[str, Any] | None = None) -> list[Any]:
        result = self._call(method, params)
        return list(result) if isinstance(result, list) else []

    def _call_with_progress(
        self,
        method: str,
        params: dict[str, Any],
        on_progress: Any,
    ) -> Any:
        """Run a long RPC while polling ``progress.get`` and relaying updates."""
        token = uuid.uuid4().hex
        box: dict[str, Any] = {}

        def _run() -> None:
            try:
                box["result"] = self._call(method, {**params, "progress_token": token})
            except BaseException as exc:  # noqa: BLE001 — re-raised on caller thread
                box["error"] = exc

        worker = threading.Thread(target=_run, name=f"rpc-{method}", daemon=True)
        worker.start()
        last_seq = 0
        while True:
            worker.join(_PROGRESS_POLL_SEC)
            try:
                snap = self._as_dict("progress.get", {"token": token})
            except RuntimeError:
                snap = {}
            seq = int(snap.get("seq") or 0)
            if seq > last_seq:
                last_seq = seq
                stage = str(snap.get("stage") or "")
                percent = int(snap.get("percent") or 0)
                if stage or percent:
                    on_progress(stage, percent)
            if not worker.is_alive():
                break
        if "error" in box:
            raise box["error"]
        return box.get("result")

    def pack_install(
        self,
        name: str,
        *,
        confirm_aur: bool = False,
        on_progress: Any = None,
    ) -> dict[str, Any]:
        params = {"name": name, "confirm_aur": confirm_aur}
        if on_progress is not None:
            result = self._call_with_progress("pack.install", params, on_progress)
            return dict(result) if isinstance(result, dict) else {}
        return self._as_dict("pack.install", params)

    def start_scan(
        self,
        profile: str = "quick",
        paths: list[str] | None = None,
        quarantine: bool = False,
        packs: list[str] | None = None,
        *,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        cfg = load_config()
        params: dict[str, Any] = {
            "profile": profile,
            "paths": paths,
            "quarantine": quarantine,
            "packs": packs,
            "backend": cfg.scan.backend,
        }
        if job_id:
            params["job_id"] = job_id
        raw = self._request("job.start", params)
        result = self._result(raw)
        if isinstance(result, dict) and "scan" in result:
            return result
        if isinstance(result, dict) and "job_id" in result:
            return {"scan": result, "exit_code": int(result.get("exit_code", 0))}
        return {"scan": {}, "exit_code": 2}

    def runtime_install(
        self,
        pack: str | None = None,
        *,
        packs: list[str] | None = None,
        on_progress: Any = None,
    ) -> Any:
        params: dict[str, Any] = {}
        if pack:
            params["pack"] = pack
        if packs:
            params["packs"] = list(packs)
        if on_progress is not None:
            return self._call_with_progress("runtime.install", params, on_progress)
        return self._call("runtime.install", params)

    def runtime_remove(self, pack: str, *, on_progress: Any = None) -> dict[str, Any]:
        params = {"pack": pack}
        if on_progress is not None:
            result = self._call_with_progress("runtime.remove", params, on_progress)
            return dict(result) if isinstance(result, dict) else {}
        return self._as_dict("runtime.remove", params)

    def runtime_bootstrap(self, **kwargs: Any) -> dict[str, Any]:
        on_progress = kwargs.pop("on_progress", None)
        if on_progress is not None:
            result = self._call_with_progress("runtime.bootstrap", kwargs, on_progress)
            return dict(result) if isinstance(result, dict) else {}
        return self._as_dict("runtime.bootstrap", kwargs)
