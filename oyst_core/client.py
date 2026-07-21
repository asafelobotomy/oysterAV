"""OystClient — JSON-RPC client for oyst-cli serve."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from oyst_core.client_api import OystClientApi
from oyst_core.config import data_dir, load_config
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_auth import ensure_rpc_token, load_rpc_token
from oyst_core.rpc_errors import RpcError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_io import recv_framed, timeout_for_method

DEFAULT_SOCKET = data_dir() / "oyst.sock"


class OystClient(OystClientApi):
    def __init__(self, socket_path: Path | None = None) -> None:
        self.socket_path = socket_path or DEFAULT_SOCKET
        self._orchestrator = JobOrchestrator()

    def _auth_token(self) -> str | None:
        return load_rpc_token() or ensure_rpc_token()

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if not self.socket_path.exists():
            return self._local_fallback(method, params)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout_for_method(method))
            sock.connect(str(self.socket_path))
        except OSError:
            return self._local_fallback(method, params)
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

    def pack_install(
        self,
        name: str,
        *,
        confirm_aur: bool = False,
        on_progress: Any = None,
    ) -> dict[str, Any]:
        if on_progress is not None:
            from oyst_core.pack_install import install_pack

            return install_pack(name, confirm_aur=confirm_aur, on_progress=on_progress).model_dump()
        return self._as_dict("pack.install", {"name": name, "confirm_aur": confirm_aur})

    def start_scan(
        self,
        profile: str = "quick",
        paths: list[str] | None = None,
        quarantine: bool = False,
        packs: list[str] | None = None,
    ) -> dict[str, Any]:
        cfg = load_config()
        raw = self._request(
            "job.start",
            {
                "profile": profile,
                "paths": paths,
                "quarantine": quarantine,
                "packs": packs,
                "backend": cfg.scan.backend,
            },
        )
        result = self._result(raw)
        if isinstance(result, dict) and "scan" in result:
            return result
        if isinstance(result, dict) and "job_id" in result:
            return {"scan": result, "exit_code": int(raw.get("exit_code", 0))}
        return {"scan": {}, "exit_code": 2}

    def runtime_install(
        self,
        pack: str | None = None,
        *,
        packs: list[str] | None = None,
        on_progress: Any = None,
    ) -> Any:
        if on_progress is not None:
            from oyst_core.runtime.bootstrap import bootstrap_runtime, install_pack_runtime

            if pack:
                return install_pack_runtime(str(pack), on_progress=on_progress)
            results = bootstrap_runtime(
                list(packs) if packs else None,
                on_progress=on_progress,
            )
            ok_count = sum(1 for r in results if r.get("ok"))
            return {
                "ok": ok_count == len(results) and bool(results),
                "results": results,
                "message": f"Installed {ok_count}/{len(results)} runtime packs",
            }
        params: dict[str, Any] = {}
        if pack:
            params["pack"] = pack
        if packs:
            params["packs"] = list(packs)
        return self._call("runtime.install", params)

    def runtime_remove(self, pack: str, *, on_progress: Any = None) -> dict[str, Any]:
        if on_progress is not None:
            from oyst_core.runtime.bootstrap import remove_pack_runtime

            result = remove_pack_runtime(pack, on_progress=on_progress)
            return dict(result) if isinstance(result, dict) else {}
        return self._as_dict("runtime.remove", {"pack": pack})

    def runtime_bootstrap(self, **kwargs: Any) -> dict[str, Any]:
        on_progress = kwargs.pop("on_progress", None)
        if on_progress is not None:
            from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap

            result = run_full_runtime_bootstrap(on_progress=on_progress, **kwargs)
            return dict(result) if isinstance(result, dict) else {}
        return self._as_dict("runtime.bootstrap", kwargs)
