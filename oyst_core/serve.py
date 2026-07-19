"""JSON-RPC serve mode for GUI clients."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any, Literal

from oyst_core.audit import SecurityAudit
from oyst_core.config import data_dir, get_config_value, load_config, set_config_value, setup_status
from oyst_core.events import EventLog
from oyst_core.health import assess_health
from oyst_core.models import ScanProfile
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.pack_install import install_pack
from oyst_core.pack_jobs import (
    run_rkhunter_propupd,
    run_rkhunter_resolve,
    run_rkhunter_scan,
    run_rkhunter_update,
)
from oyst_core.quarantine import QuarantineVault
from oyst_core.rpc_auth import ensure_rpc_token, verify_peer_credentials, verify_rpc_token
from oyst_core.rpc_errors import RpcError
from oyst_core.rpc_io import recv_framed
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap
from oyst_core.schedule_util import (
    apply_schedule,
    enable_linger,
    get_linger_status,
    get_schedule_status,
    install_user_timer,
    run_scheduled_scan,
)
from oyst_core.setup_workflow import run_setup

SCHEMA_VERSION = 2
DEFAULT_SOCKET = data_dir() / "oyst.sock"
_logger = logging.getLogger("oyst.rpc")


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
        audit = SecurityAudit()
        if method == "status":
            return self.orchestrator.aggregate_status()
        if method == "status.assess":
            status = self.orchestrator.aggregate_status()
            return assess_health(status)
        if method == "pack.doctor":
            from oyst_core.doctor_cache import doctor_all

            return doctor_all()
        if method == "pack.install":
            from oyst_core.doctor_cache import invalidate_doctor_cache

            install_result = install_pack(
                str(params["name"]),
                confirm_aur=bool(params.get("confirm_aur", False)),
            )
            invalidate_doctor_cache()
            audit.log(
                "pack.install",
                str(params["name"]),
                success=install_result.ok,
                data={"mode": install_result.mode, "strategy": install_result.strategy},
            )
            return install_result.model_dump()
        if method == "setup.status":
            return setup_status()
        if method == "setup.run":
            from oyst_core.doctor_cache import invalidate_doctor_cache

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
            return result
        if method == "job.start":
            scan_profile = ScanProfile(params.get("profile", "quick"))
            cfg = load_config()
            backend = str(params.get("backend", cfg.scan.backend))
            scan_result, code = self.orchestrator.run_scan(
                profile=scan_profile,
                paths=params.get("paths"),
                packs=params.get("packs"),
                quarantine=bool(params.get("quarantine")),
                backend=backend,
            )
            return {"scan": scan_result.model_dump(mode="json"), "exit_code": int(code)}
        if method == "job.cancel":
            return self.orchestrator.cancel_job(params.get("job_id"))
        if method == "job.status":
            return self.orchestrator.job_status()
        if method == "rkhunter.scan":
            return run_rkhunter_scan()
        if method == "rkhunter.update":
            return run_rkhunter_update()
        if method == "rkhunter.propupd":
            return run_rkhunter_propupd()
        if method == "rkhunter.resolve":
            return run_rkhunter_resolve(
                str(params.get("threat_name") or ""),
                path=str(params.get("path") or ""),
                message=str(params.get("message") or ""),
                force=bool(params.get("force", False)),
                dry_run=bool(params.get("dry_run", False)),
                job_id=str(params["job_id"]) if params.get("job_id") else None,
            )
        if method == "quarantine.list":
            return [e.model_dump(mode="json") for e in QuarantineVault().list_entries()]
        if method == "quarantine.restore":
            entry_id = int(params["id"])
            dest = QuarantineVault().restore(entry_id)
            return str(dest)
        if method == "maintenance.bootstrap":
            from oyst_core.maintenance import run_bootstrap

            return run_bootstrap(skip_lynis=bool(params.get("skip_lynis")))
        if method == "maintenance.post-update":
            from oyst_core.maintenance import run_post_update

            return run_post_update()
        if method == "history.list":
            limit = int(params.get("limit", 20))
            return EventLog().history(limit=limit)
        if method == "history.get":
            from oyst_core.rpc_errors import RpcNotFoundError

            job_id = str(params.get("job_id") or "")
            if not job_id:
                raise RpcNotFoundError("scan not found: (missing job_id)")
            scan = EventLog().get_scan(job_id)
            if scan is None:
                raise RpcNotFoundError(f"scan not found: {job_id}")
            return scan
        if method == "history.handle_open":
            from oyst_core.history_actions import handle_open_findings

            return handle_open_findings(
                str(params.get("job_id") or ""),
                quarantine=bool(params.get("quarantine", False)),
                resolve=bool(params.get("resolve", False)),
                force=bool(params.get("force", False)),
            )
        if method == "history.delete":
            return EventLog().delete_scan(str(params.get("job_id") or ""))
        if method == "history.delete_all":
            return EventLog().delete_all_scans()
        if method == "history.export":
            from oyst_core.history_export import export_scan_to_path

            return export_scan_to_path(
                str(params.get("job_id") or ""),
                str(params.get("path") or ""),
                fmt=str(params.get("format") or "json"),
            )
        if method == "history.export_all":
            from oyst_core.history_export import export_all_scans_to_path

            return export_all_scans_to_path(
                str(params.get("path") or ""),
                fmt=str(params.get("format") or "json"),
                limit=int(params.get("limit", 500)),
            )
        if method == "audit.list":
            limit = int(params.get("limit", 50))
            return SecurityAudit().list_entries(limit=limit)
        if method == "quarantine.delete":
            entry_id = int(params["id"])
            QuarantineVault().delete(entry_id)
            return True
        if method == "quarantine.verify":
            bad = QuarantineVault().verify()
            return {"invalid_entries": bad, "ok": len(bad) == 0}
        if method == "quarantine.add":
            from oyst_core.history_actions import quarantine_and_patch

            entry = quarantine_and_patch(
                str(params["path"]),
                str(params.get("threat_name") or params.get("threat") or ""),
                job_id=str(params["job_id"]) if params.get("job_id") else None,
                pack=str(params.get("pack") or ""),
                message=str(params.get("message") or ""),
            )
            audit.log("quarantine.add", str(params["path"]), success=True)
            return entry
        if method == "desktop.status":
            from oyst_core.desktop_util import autostart_status

            return autostart_status()
        if method == "config.get":
            key = params.get("key")
            if key:
                val = get_config_value(str(key))
                if val is None:
                    from oyst_core.rpc_errors import RpcNotFoundError

                    raise RpcNotFoundError(f"unknown config key: {key}")
                return val
            return load_config().model_dump()
        if method == "config.set":
            key = str(params["key"])
            value = str(params["value"])
            set_config_value(key, value)
            return True
        if method == "schedule.install":
            timer_profile = str(params.get("profile", "quick"))
            return install_user_timer(timer_profile, smoke_test=True)
        if method == "schedule.apply":
            return apply_schedule(smoke_test=bool(params.get("smoke_test", False)))
        if method == "schedule.status":
            return get_schedule_status()
        if method == "schedule.run":
            return run_scheduled_scan()
        if method == "schedule.linger":
            return get_linger_status()
        if method == "schedule.enable_linger":
            return enable_linger()
        if method == "runtime.status":
            from oyst_core.runtime.bootstrap import runtime_status

            return runtime_status()
        if method == "runtime.install":
            from oyst_core.runtime.bootstrap import bootstrap_runtime, install_pack_runtime

            pack = params.get("pack")
            if pack:
                return install_pack_runtime(str(pack))
            return bootstrap_runtime()
        if method == "runtime.remove":
            from oyst_core.runtime.bootstrap import remove_pack_runtime

            return remove_pack_runtime(str(params["pack"]))
        if method == "runtime.update":
            from oyst_core.runtime.bootstrap import update_runtime

            return update_runtime()
        if method == "runtime.bootstrap":
            return run_full_runtime_bootstrap(
                skip_install=bool(params.get("skip_install", False)),
                update_signatures=bool(params.get("update_signatures", True)),
                run_maintenance=bool(params.get("run_maintenance", True)),
                skip_lynis=bool(params.get("skip_lynis", True)),
            )
        if method == "firewall.status":
            from oyst_core.packs.firewall import FirewallPack

            return FirewallPack().status()
        if method == "fail2ban.unban":
            from oyst_core.packs.fail2ban import Fail2banPack

            ok, msg = Fail2banPack().unban(
                str(params["ip"]),
                jail=params.get("jail"),
                ignore=bool(params.get("ignore", False)),
                persist=bool(params.get("persist", False)),
            )
            audit.log(
                "fail2ban.unban", str(params["ip"]), success=ok, data={"jail": params.get("jail")}
            )
            return {"ok": ok, "message": msg}
        if method == "clamav.clamd.ensure":
            from oyst_core.packs.clamav import ClamAVPack

            ok, msg = ClamAVPack().clamd_ensure()
            audit.log("clamav.clamd", "ensure", success=ok)
            return {"ok": ok, "message": msg, "status": ClamAVPack().clamd_status()}
        if method == "services.status":
            from oyst_core.services import services_status

            return services_status()
        if method == "services.set":
            from oyst_core.rpc_errors import RpcValidationError
            from oyst_core.services import SERVICE_NAMES, set_service

            name = str(params.get("name", ""))
            state = str(params.get("state", ""))
            if name not in SERVICE_NAMES:
                raise RpcValidationError(f"unknown service: {name}")
            if state not in ("on", "off"):
                raise RpcValidationError("state must be on or off")
            state_lit: Literal["on", "off"] = "on" if state == "on" else "off"
            return set_service(name, state_lit, boot=bool(params.get("boot", False)))
        if method == "auth.status":
            from oyst_core.privileged.auth_grant import auth_status
            from oyst_core.privileged.install_privileged_helper import helper_status

            return {"helper": helper_status(), "service_lifecycle": auth_status()}
        if method == "helper.install":
            from oyst_core.privileged.elevate_cli import install_helper_elevated

            return install_helper_elevated()
        if method == "auth.grant_service_lifecycle":
            from oyst_core.privileged.elevate_cli import grant_service_lifecycle_elevated

            user = params.get("user")
            return grant_service_lifecycle_elevated(str(user) if user is not None else None)
        if method == "auth.revoke_service_lifecycle":
            from oyst_core.privileged.elevate_cli import revoke_service_lifecycle_elevated

            return revoke_service_lifecycle_elevated()
        if method == "clamonacc.status":
            from oyst_core.packs.clamonacc import ClamonaccPack

            return ClamonaccPack().doctor().model_dump()
        if method == "clamonacc.start":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().start()
            return {"ok": ok, "message": msg}
        if method == "clamonacc.stop":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().stop()
            return {"ok": ok, "message": msg}
        if method == "clamonacc.enable":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().enable()
            audit.log("clamonacc", "enable", success=ok)
            return {"ok": ok, "message": msg}
        if method == "clamonacc.disable":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ok, msg = ClamonaccPack().disable()
            audit.log("clamonacc", "disable", success=ok)
            return {"ok": ok, "message": msg}
        if method == "clamonacc.add_path":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ClamonaccPack().add_path(str(params["path"]))
            return True
        if method == "clamonacc.remove_path":
            from oyst_core.packs.clamonacc import ClamonaccPack

            ClamonaccPack().remove_path(str(params["path"]))
            return True
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
            return list_security_news(
                force_refresh=bool(params.get("force", False)),
                sources=sources,
            )
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
            return list_security_news(force_refresh=True, sources=sources)
        if method == "updates.check":
            from oyst_core.updates import check_available_updates

            return check_available_updates()
        if method == "updates.apply":
            from oyst_core.updates import apply_all_updates

            return apply_all_updates()
        from oyst_core.rpc_errors import RpcNotFoundError

        raise RpcNotFoundError(f"unknown method: {method}")

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
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        with conn:
            try:
                verify_peer_credentials(conn)
            except RpcError as exc:
                response = {
                    "id": 0,
                    "schema_version": SCHEMA_VERSION,
                    "error": exc.to_dict(),
                }
                conn.sendall((json.dumps(response) + "\n").encode())
                return
            data = recv_framed(conn).decode()
            if not data.strip():
                return
            request = json.loads(data)
            response = self.handle(request)
            conn.sendall((json.dumps(response) + "\n").encode())

    def stop(self) -> None:
        self._running = False
