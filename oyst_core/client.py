"""OystClient — JSON-RPC client for oyst-cli serve."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Literal, cast

from oyst_core.config import data_dir, get_config_value, load_config, set_config_value, setup_status
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.rpc_auth import ensure_rpc_token, load_rpc_token
from oyst_core.rpc_io import recv_framed, timeout_for_method
from oyst_core.schedule_util import (
    apply_schedule,
    enable_linger,
    get_linger_status,
    get_schedule_status,
    install_user_timer,
    run_scheduled_scan,
)
from oyst_core.services import SERVICE_NAMES, ServiceName, set_service

DEFAULT_SOCKET = data_dir() / "oyst.sock"


class OystClient:
    def __init__(self, socket_path: Path | None = None) -> None:
        self.socket_path = socket_path or DEFAULT_SOCKET
        self._orchestrator = JobOrchestrator()

    def _auth_token(self) -> str | None:
        return load_rpc_token() or ensure_rpc_token()

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        if self.socket_path.exists():
            try:
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
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout_for_method(method))
                    sock.connect(str(self.socket_path))
                    sock.sendall(payload.encode())
                    data = recv_framed(sock).decode()
                if not data.strip():
                    raise OSError("empty RPC response")
                return json.loads(data)  # type: ignore[no-any-return]
            except (OSError, json.JSONDecodeError):
                pass
        return self._local_fallback(method, params)

    def _local_fallback(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "status":
            return {"result": self._orchestrator.aggregate_status()}
        if method == "status.assess":
            from oyst_core.health import assess_health

            status = self._orchestrator.aggregate_status()
            return {"result": assess_health(status)}
        if method == "pack.doctor":
            from oyst_core.doctor_cache import doctor_all

            return {"result": doctor_all()}
        if method == "pack.install":
            from oyst_core.doctor_cache import invalidate_doctor_cache
            from oyst_core.pack_install import install_pack

            install_result = install_pack(
                str(params["name"]),
                confirm_aur=bool(params.get("confirm_aur", False)),
            )
            invalidate_doctor_cache()
            return {"result": install_result.model_dump()}
        if method == "setup.status":
            return {"result": setup_status()}
        if method == "setup.run":
            from oyst_core.doctor_cache import invalidate_doctor_cache
            from oyst_core.setup_workflow import run_setup

            result = run_setup(
                skip_packs=bool(params.get("skip_packs", False)),
                skip_schedule=bool(params.get("skip_schedule", False)),
                skip_bootstrap=bool(params.get("skip_bootstrap", False)),
                confirm_aur=bool(params.get("confirm_aur", False)),
                auto_quarantine=params.get("auto_quarantine"),
                schedule_profile=str(params.get("schedule_profile", "quick")),
                full_bootstrap=bool(params.get("full_bootstrap", True)),
                enable_linger=bool(params.get("enable_linger", False)),
                mark_complete=bool(params.get("mark_complete", True)),
            )
            invalidate_doctor_cache()
            return {"result": result}
        if method == "job.start":
            scan_profile_name = params.get("profile", "quick")
            paths = params.get("paths")
            from oyst_core.models import ScanProfile

            cfg = load_config()
            backend = str(params.get("backend", cfg.scan.backend))
            scan_result, code = self._orchestrator.run_scan(
                profile=ScanProfile(scan_profile_name),
                paths=paths,
                packs=params.get("packs"),
                quarantine=bool(params.get("quarantine")),
                backend=backend,
            )
            return {
                "result": {
                    "scan": scan_result.model_dump(mode="json"),
                    "exit_code": int(code),
                },
            }
        if method == "job.cancel":
            return {"result": self._orchestrator.cancel_job(params.get("job_id"))}
        if method == "job.status":
            return {"result": self._orchestrator.job_status()}
        if method == "rkhunter.scan":
            from oyst_core.pack_jobs import run_rkhunter_scan

            return {"result": run_rkhunter_scan()}
        if method == "rkhunter.update":
            from oyst_core.pack_jobs import run_rkhunter_update

            return {"result": run_rkhunter_update()}
        if method == "rkhunter.propupd":
            from oyst_core.pack_jobs import run_rkhunter_propupd

            return {"result": run_rkhunter_propupd()}
        if method == "rkhunter.resolve":
            from oyst_core.pack_jobs import run_rkhunter_resolve

            return {
                "result": run_rkhunter_resolve(
                    str(params.get("threat_name") or ""),
                    path=str(params.get("path") or ""),
                    message=str(params.get("message") or ""),
                    force=bool(params.get("force", False)),
                    dry_run=bool(params.get("dry_run", False)),
                    job_id=str(params["job_id"]) if params.get("job_id") else None,
                )
            }
        if method == "quarantine.list":
            from oyst_core.quarantine import QuarantineVault

            entries = QuarantineVault().list_entries()
            return {"result": [e.model_dump(mode="json") for e in entries]}
        if method == "quarantine.restore":
            from oyst_core.quarantine import QuarantineVault

            dest = QuarantineVault().restore(int(params["id"]))
            return {"result": str(dest)}
        if method == "quarantine.delete":
            from oyst_core.quarantine import QuarantineVault

            QuarantineVault().delete(int(params["id"]))
            return {"result": True}
        if method == "quarantine.verify":
            from oyst_core.quarantine import QuarantineVault

            bad = QuarantineVault().verify()
            return {"result": {"invalid_entries": bad, "ok": len(bad) == 0}}
        if method == "quarantine.add":
            from oyst_core.history_actions import quarantine_and_patch

            return {
                "result": quarantine_and_patch(
                    str(params["path"]),
                    str(params.get("threat_name") or params.get("threat") or ""),
                    job_id=str(params["job_id"]) if params.get("job_id") else None,
                    pack=str(params.get("pack") or ""),
                    message=str(params.get("message") or ""),
                )
            }
        if method == "desktop.status":
            from oyst_core.desktop_util import autostart_status

            return {"result": autostart_status()}
        if method == "maintenance.bootstrap":
            from oyst_core.maintenance import run_bootstrap

            steps = run_bootstrap(skip_lynis=bool(params.get("skip_lynis")))
            return {"result": steps}
        if method == "maintenance.post-update":
            from oyst_core.maintenance import run_post_update

            return {"result": run_post_update()}
        if method == "history.list":
            from oyst_core.events import EventLog

            limit = int(params.get("limit", 20))
            return {"result": EventLog().history(limit=limit)}
        if method == "history.get":
            from oyst_core.events import EventLog

            job_id = str(params.get("job_id") or "")
            scan = EventLog().get_scan(job_id) if job_id else None
            if scan is None:
                return {
                    "error": {
                        "code": -32004,
                        "message": f"scan not found: {job_id or '(missing job_id)'}",
                    }
                }
            return {"result": scan}
        if method == "history.handle_open":
            from oyst_core.history_actions import handle_open_findings

            return {
                "result": handle_open_findings(
                    str(params.get("job_id") or ""),
                    quarantine=bool(params.get("quarantine", False)),
                    resolve=bool(params.get("resolve", False)),
                    force=bool(params.get("force", False)),
                )
            }
        if method == "history.delete":
            from oyst_core.events import EventLog

            return {"result": EventLog().delete_scan(str(params.get("job_id") or ""))}
        if method == "history.delete_all":
            from oyst_core.events import EventLog

            return {"result": EventLog().delete_all_scans()}
        if method == "history.export":
            from oyst_core.history_export import export_scan_to_path

            return {
                "result": export_scan_to_path(
                    str(params.get("job_id") or ""),
                    str(params.get("path") or ""),
                    fmt=str(params.get("format") or "json"),
                )
            }
        if method == "history.export_all":
            from oyst_core.history_export import export_all_scans_to_path

            return {
                "result": export_all_scans_to_path(
                    str(params.get("path") or ""),
                    fmt=str(params.get("format") or "json"),
                    limit=int(params.get("limit", 500)),
                )
            }
        if method == "audit.list":
            from oyst_core.audit import SecurityAudit

            limit = int(params.get("limit", 50))
            return {"result": SecurityAudit().list_entries(limit=limit)}
        if method == "config.get":
            key = params.get("key")
            if key:
                val = get_config_value(str(key))
                if val is None:
                    return {"error": {"code": "not_found", "message": f"unknown config key: {key}"}}
                return {"result": val}
            return {"result": load_config().model_dump()}
        if method == "config.set":
            set_config_value(str(params["key"]), str(params["value"]))
            return {"result": True}
        if method == "schedule.install":
            profile = str(params.get("profile", "quick"))
            return {"result": install_user_timer(profile, smoke_test=True)}
        if method == "schedule.apply":
            return {
                "result": apply_schedule(smoke_test=bool(params.get("smoke_test", False))),
            }
        if method == "schedule.status":
            return {"result": get_schedule_status()}
        if method == "schedule.run":
            return {"result": run_scheduled_scan()}
        if method == "schedule.linger":
            return {"result": get_linger_status()}
        if method == "schedule.enable_linger":
            return {"result": enable_linger()}
        if method == "runtime.status":
            from oyst_core.runtime.bootstrap import runtime_status

            return {"result": runtime_status()}
        if method == "runtime.install":
            from oyst_core.runtime.bootstrap import bootstrap_runtime, install_pack_runtime

            pack = params.get("pack")
            if pack:
                return {"result": install_pack_runtime(str(pack))}
            return {"result": bootstrap_runtime()}
        if method == "runtime.remove":
            from oyst_core.runtime.bootstrap import remove_pack_runtime

            return {"result": remove_pack_runtime(str(params["pack"]))}
        if method == "runtime.update":
            from oyst_core.runtime.bootstrap import update_runtime

            return {"result": update_runtime()}
        if method == "runtime.bootstrap":
            from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap

            return {
                "result": run_full_runtime_bootstrap(
                    skip_install=bool(params.get("skip_install", False)),
                    update_signatures=bool(params.get("update_signatures", True)),
                    run_maintenance=bool(params.get("run_maintenance", True)),
                    skip_lynis=bool(params.get("skip_lynis", True)),
                ),
            }
        if method == "firewall.status":
            from oyst_core.packs.firewall import FirewallPack

            return {"result": FirewallPack().status()}
        if method == "fail2ban.unban":
            from oyst_core.packs.fail2ban import Fail2banPack

            ok, msg = Fail2banPack().unban(
                str(params["ip"]),
                jail=params.get("jail"),
                ignore=bool(params.get("ignore", False)),
                persist=bool(params.get("persist", False)),
            )
            return {"result": {"ok": ok, "message": msg}}
        if method == "clamav.clamd.ensure":
            from oyst_core.packs.clamav import ClamAVPack

            ok, msg = ClamAVPack().clamd_ensure()
            return {
                "result": {
                    "ok": ok,
                    "message": msg,
                    "status": ClamAVPack().clamd_status(),
                },
            }
        if method == "services.status":
            from oyst_core.services import services_status

            return {"result": services_status()}
        if method == "services.set":
            name = str(params.get("name", ""))
            state = str(params.get("state", ""))
            if name not in SERVICE_NAMES or state not in ("on", "off"):
                return {
                    "error": {
                        "code": "validation_error",
                        "message": "invalid services.set params",
                    },
                }
            state_lit: Literal["on", "off"] = "on" if state == "on" else "off"
            return {
                "result": set_service(
                    cast(ServiceName, name),
                    state_lit,
                    boot=bool(params.get("boot", False)),
                ),
            }
        if method == "auth.status":
            from oyst_core.privileged.auth_grant import auth_status
            from oyst_core.privileged.install_privileged_helper import helper_status

            return {
                "result": {"helper": helper_status(), "service_lifecycle": auth_status()},
            }
        if method == "helper.install":
            from oyst_core.privileged.elevate_cli import install_helper_elevated

            return {"result": install_helper_elevated()}
        if method == "auth.grant_service_lifecycle":
            from oyst_core.privileged.elevate_cli import grant_service_lifecycle_elevated

            user = params.get("user")
            return {
                "result": grant_service_lifecycle_elevated(
                    str(user) if user is not None else None,
                ),
            }
        if method == "auth.revoke_service_lifecycle":
            from oyst_core.privileged.elevate_cli import revoke_service_lifecycle_elevated

            return {"result": revoke_service_lifecycle_elevated()}
        if method == "clamonacc.status":
            from oyst_core.packs.clamonacc import ClamonaccPack

            return {"result": ClamonaccPack().doctor().model_dump()}
        if method == "clamonacc.start":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().start()
            return {"result": {"ok": ok, "message": msg}}
        if method == "clamonacc.stop":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().stop()
            return {"result": {"ok": ok, "message": msg}}
        if method == "clamonacc.enable":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().enable()
            return {"result": {"ok": ok, "message": msg}}
        if method == "clamonacc.disable":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().disable()
            return {"result": {"ok": ok, "message": msg}}
        if method == "clamonacc.add_path":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ClamonaccPack().add_path(str(params["path"]))
            return {"result": True}
        if method == "clamonacc.remove_path":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ClamonaccPack().remove_path(str(params["path"]))
            return {"result": True}
        if method == "news.list":
            from oyst_core.security_news import list_security_news, normalize_source_ids

            raw_sources = params.get("sources")
            sources = None
            if isinstance(raw_sources, list):
                sources = normalize_source_ids([str(s) for s in raw_sources])
            elif isinstance(raw_sources, str) and raw_sources.strip():
                sources = normalize_source_ids(
                    [s.strip() for s in raw_sources.split(",") if s.strip()],
                )
            return {
                "result": list_security_news(
                    force_refresh=bool(params.get("force", False)),
                    sources=sources,
                ),
            }
        if method == "news.refresh":
            from oyst_core.security_news import list_security_news, normalize_source_ids

            raw_sources = params.get("sources")
            sources = None
            if isinstance(raw_sources, list):
                sources = normalize_source_ids([str(s) for s in raw_sources])
            elif isinstance(raw_sources, str) and raw_sources.strip():
                sources = normalize_source_ids(
                    [s.strip() for s in raw_sources.split(",") if s.strip()],
                )
            return {"result": list_security_news(force_refresh=True, sources=sources)}
        if method == "updates.check":
            from oyst_core.updates import check_available_updates

            return {"result": check_available_updates()}
        if method == "updates.apply":
            from oyst_core.updates import apply_all_updates

            return {"result": apply_all_updates()}
        return {"error": {"code": "not_found", "message": f"unknown method: {method}"}}

    def _result(self, response: dict[str, Any]) -> Any:
        if "error" in response:
            err = response["error"]
            if isinstance(err, dict):
                raise RuntimeError(str(err.get("message", err)))
            raise RuntimeError(str(err))
        return response.get("result")

    def status(self) -> dict[str, Any]:
        result = self._result(self._request("status"))
        return dict(result) if isinstance(result, dict) else {}

    def status_assess(self) -> dict[str, Any]:
        result = self._result(self._request("status.assess"))
        return dict(result) if isinstance(result, dict) else {}

    def doctor(self) -> list[dict[str, Any]]:
        result = self._result(self._request("pack.doctor"))
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

            result = install_pack(name, confirm_aur=confirm_aur, on_progress=on_progress)
            return result.model_dump()
        result = self._result(
            self._request("pack.install", {"name": name, "confirm_aur": confirm_aur}),
        )
        return dict(result) if isinstance(result, dict) else {}

    def setup_status(self) -> dict[str, Any]:
        result = self._result(self._request("setup.status"))
        return dict(result) if isinstance(result, dict) else {}

    def setup_run(self, **kwargs: Any) -> dict[str, Any]:
        result = self._result(self._request("setup.run", kwargs))
        return dict(result) if isinstance(result, dict) else {}

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

    def cancel_job(self, job_id: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if job_id is not None:
            params["job_id"] = job_id
        result = self._result(self._request("job.cancel", params))
        return dict(result) if isinstance(result, dict) else {}

    def job_status(self) -> dict[str, Any]:
        result = self._result(self._request("job.status"))
        return dict(result) if isinstance(result, dict) else {}

    def rkhunter_scan(self) -> dict[str, Any]:
        result = self._result(self._request("rkhunter.scan"))
        return dict(result) if isinstance(result, dict) else {}

    def rkhunter_update(self) -> dict[str, Any]:
        result = self._result(self._request("rkhunter.update"))
        return dict(result) if isinstance(result, dict) else {}

    def rkhunter_propupd(self) -> dict[str, Any]:
        result = self._result(self._request("rkhunter.propupd"))
        return dict(result) if isinstance(result, dict) else {}

    def rkhunter_resolve(
        self,
        threat_name: str,
        *,
        path: str = "",
        message: str = "",
        force: bool = False,
        dry_run: bool = False,
        job_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threat_name": threat_name,
            "path": path,
            "message": message,
            "force": force,
            "dry_run": dry_run,
        }
        if job_id:
            params["job_id"] = job_id
        result = self._result(self._request("rkhunter.resolve", params))
        return dict(result) if isinstance(result, dict) else {}

    def history_list(self, limit: int = 20) -> list[dict[str, Any]]:
        result = self._result(self._request("history.list", {"limit": limit}))
        return list(result) if isinstance(result, list) else []

    def history_get(self, job_id: str) -> dict[str, Any]:
        result = self._result(self._request("history.get", {"job_id": job_id}))
        return dict(result) if isinstance(result, dict) else {}

    def history_handle_open(
        self,
        job_id: str,
        *,
        quarantine: bool = False,
        resolve: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        result = self._result(
            self._request(
                "history.handle_open",
                {
                    "job_id": job_id,
                    "quarantine": quarantine,
                    "resolve": resolve,
                    "force": force,
                },
            )
        )
        return dict(result) if isinstance(result, dict) else {}

    def history_delete(self, job_id: str) -> dict[str, Any]:
        result = self._result(self._request("history.delete", {"job_id": job_id}))
        return dict(result) if isinstance(result, dict) else {}

    def history_delete_all(self) -> dict[str, Any]:
        result = self._result(self._request("history.delete_all"))
        return dict(result) if isinstance(result, dict) else {}

    def history_export(
        self,
        job_id: str,
        path: str,
        *,
        fmt: str = "json",
    ) -> dict[str, Any]:
        result = self._result(
            self._request(
                "history.export",
                {"job_id": job_id, "path": path, "format": fmt},
            )
        )
        return dict(result) if isinstance(result, dict) else {}

    def history_export_all(
        self,
        path: str,
        *,
        fmt: str = "json",
        limit: int = 500,
    ) -> dict[str, Any]:
        result = self._result(
            self._request(
                "history.export_all",
                {"path": path, "format": fmt, "limit": limit},
            )
        )
        return dict(result) if isinstance(result, dict) else {}

    def audit_list(self, limit: int = 50) -> list[dict[str, Any]]:
        result = self._result(self._request("audit.list", {"limit": limit}))
        return list(result) if isinstance(result, list) else []

    def quarantine_list(self) -> list[dict[str, Any]]:
        result = self._result(self._request("quarantine.list"))
        return list(result) if isinstance(result, list) else []

    def quarantine_restore(self, entry_id: int) -> str:
        result = self._result(self._request("quarantine.restore", {"id": entry_id}))
        return str(result)

    def quarantine_delete(self, entry_id: int) -> None:
        self._result(self._request("quarantine.delete", {"id": entry_id}))

    def quarantine_verify(self) -> dict[str, Any]:
        result = self._result(self._request("quarantine.verify"))
        return dict(result) if isinstance(result, dict) else {"invalid_entries": [], "ok": True}

    def quarantine_add(
        self,
        path: str,
        threat_name: str = "",
        *,
        job_id: str | None = None,
        pack: str = "",
        message: str = "",
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"path": path, "threat_name": threat_name}
        if job_id:
            params["job_id"] = job_id
        if pack:
            params["pack"] = pack
        if message:
            params["message"] = message
        result = self._result(self._request("quarantine.add", params))
        return dict(result) if isinstance(result, dict) else {}

    def desktop_status(self) -> dict[str, Any]:
        result = self._result(self._request("desktop.status"))
        return dict(result) if isinstance(result, dict) else {}

    def config_get(self, key: str | None = None) -> Any:
        params: dict[str, Any] = {}
        if key is not None:
            params["key"] = key
        return self._result(self._request("config.get", params))

    def config_set(self, key: str, value: str) -> None:
        self._result(self._request("config.set", {"key": key, "value": value}))

    def schedule_install(self, profile: str = "quick") -> dict[str, Any]:
        result = self._result(self._request("schedule.install", {"profile": profile}))
        return dict(result) if isinstance(result, dict) else {}

    def schedule_apply(self, *, smoke_test: bool = False) -> dict[str, Any]:
        result = self._result(
            self._request("schedule.apply", {"smoke_test": smoke_test}),
        )
        return dict(result) if isinstance(result, dict) else {}

    def schedule_status(self, profile: str = "quick") -> dict[str, Any]:
        _ = profile
        result = self._result(self._request("schedule.status", {}))
        return dict(result) if isinstance(result, dict) else {}

    def schedule_run(self) -> dict[str, Any]:
        result = self._result(self._request("schedule.run", {}))
        return dict(result) if isinstance(result, dict) else {}

    def linger_status(self) -> dict[str, Any]:
        result = self._result(self._request("schedule.linger"))
        return dict(result) if isinstance(result, dict) else {}

    def linger_enable(self) -> dict[str, Any]:
        result = self._result(self._request("schedule.enable_linger"))
        return dict(result) if isinstance(result, dict) else {}

    def runtime_status(self) -> dict[str, Any]:
        result = self._result(self._request("runtime.status"))
        return dict(result) if isinstance(result, dict) else {}

    def runtime_install(self, pack: str | None = None, *, on_progress: Any = None) -> Any:
        if on_progress is not None:
            from oyst_core.runtime.bootstrap import bootstrap_runtime, install_pack_runtime

            if pack:
                return install_pack_runtime(str(pack), on_progress=on_progress)
            return bootstrap_runtime(on_progress=on_progress)
        params: dict[str, Any] = {}
        if pack:
            params["pack"] = pack
        return self._result(self._request("runtime.install", params))

    def runtime_remove(self, pack: str, *, on_progress: Any = None) -> dict[str, Any]:
        if on_progress is not None:
            from oyst_core.runtime.bootstrap import remove_pack_runtime

            result = remove_pack_runtime(pack, on_progress=on_progress)
            return dict(result) if isinstance(result, dict) else {}
        result = self._result(self._request("runtime.remove", {"pack": pack}))
        return dict(result) if isinstance(result, dict) else {}

    def runtime_update(self) -> dict[str, Any]:
        result = self._result(self._request("runtime.update"))
        return dict(result) if isinstance(result, dict) else {}

    def runtime_bootstrap(self, **kwargs: Any) -> dict[str, Any]:
        on_progress = kwargs.pop("on_progress", None)
        if on_progress is not None:
            from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap

            result = run_full_runtime_bootstrap(on_progress=on_progress, **kwargs)
            return dict(result) if isinstance(result, dict) else {}
        result = self._result(self._request("runtime.bootstrap", kwargs))
        return dict(result) if isinstance(result, dict) else {}

    def maintenance_bootstrap(self, skip_lynis: bool = True) -> list[dict[str, object]]:
        result = self._result(
            self._request("maintenance.bootstrap", {"skip_lynis": skip_lynis}),
        )
        return list(result) if isinstance(result, list) else []

    def maintenance_post_update(self) -> list[dict[str, object]]:
        result = self._result(self._request("maintenance.post-update"))
        return list(result) if isinstance(result, list) else []

    def firewall_status(self) -> dict[str, Any]:
        result = self._result(self._request("firewall.status"))
        return dict(result) if isinstance(result, dict) else {}

    def fail2ban_unban(
        self,
        ip: str,
        *,
        jail: str | None = None,
        ignore: bool = False,
        persist: bool = False,
    ) -> dict[str, Any]:
        result = self._result(
            self._request(
                "fail2ban.unban",
                {"ip": ip, "jail": jail, "ignore": ignore, "persist": persist},
            ),
        )
        return dict(result) if isinstance(result, dict) else {}

    def clamav_clamd_ensure(self) -> dict[str, Any]:
        result = self._result(self._request("clamav.clamd.ensure"))
        return dict(result) if isinstance(result, dict) else {}

    def services_status(self) -> dict[str, Any]:
        result = self._result(self._request("services.status"))
        return dict(result) if isinstance(result, dict) else {}

    def services_set(self, name: str, state: str, *, boot: bool = False) -> dict[str, Any]:
        result = self._result(
            self._request("services.set", {"name": name, "state": state, "boot": boot}),
        )
        return dict(result) if isinstance(result, dict) else {}

    def auth_status(self) -> dict[str, Any]:
        result = self._result(self._request("auth.status"))
        return dict(result) if isinstance(result, dict) else {}

    def helper_install(self) -> dict[str, Any]:
        result = self._result(self._request("helper.install"))
        return dict(result) if isinstance(result, dict) else {}

    def auth_grant_service_lifecycle(self, user: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if user is not None:
            params["user"] = user
        result = self._result(self._request("auth.grant_service_lifecycle", params))
        return dict(result) if isinstance(result, dict) else {}

    def auth_revoke_service_lifecycle(self) -> dict[str, Any]:
        result = self._result(self._request("auth.revoke_service_lifecycle"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_status(self) -> dict[str, Any]:
        result = self._result(self._request("clamonacc.status"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_start(self) -> dict[str, Any]:
        result = self._result(self._request("clamonacc.start"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_stop(self) -> dict[str, Any]:
        result = self._result(self._request("clamonacc.stop"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_enable(self) -> dict[str, Any]:
        result = self._result(self._request("clamonacc.enable"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_disable(self) -> dict[str, Any]:
        result = self._result(self._request("clamonacc.disable"))
        return dict(result) if isinstance(result, dict) else {}

    def clamonacc_add_path(self, path: str) -> None:
        self._result(self._request("clamonacc.add_path", {"path": path}))

    def clamonacc_remove_path(self, path: str) -> None:
        self._result(self._request("clamonacc.remove_path", {"path": path}))

    def news_list(
        self,
        *,
        force: bool = False,
        sources: list[str] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"force": force}
        if sources is not None:
            params["sources"] = sources
        result = self._result(self._request("news.list", params))
        return dict(result) if isinstance(result, dict) else {}

    def news_refresh(self, *, sources: list[str] | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if sources is not None:
            params["sources"] = sources
        result = self._result(self._request("news.refresh", params))
        return dict(result) if isinstance(result, dict) else {}

    def updates_check(self) -> dict[str, Any]:
        result = self._result(self._request("updates.check"))
        return dict(result) if isinstance(result, dict) else {}

    def updates_apply(self) -> dict[str, Any]:
        result = self._result(self._request("updates.apply"))
        return dict(result) if isinstance(result, dict) else {}
