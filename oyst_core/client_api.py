"""Thin OystClient public RPC wrappers (mixin)."""

from __future__ import annotations

from typing import Any


class OystClientApi:
    """Public method façade; subclasses implement `_call` / `_as_dict` / `_as_list`."""

    def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        raise NotImplementedError

    def _as_dict(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def _as_list(self, method: str, params: dict[str, Any] | None = None) -> list[Any]:
        raise NotImplementedError

    def status(self) -> dict[str, Any]:
        return self._as_dict("status")

    def status_assess(self) -> dict[str, Any]:
        return self._as_dict("status.assess")

    def doctor(self) -> list[dict[str, Any]]:
        return self._as_list("pack.doctor")

    def setup_status(self) -> dict[str, Any]:
        return self._as_dict("setup.status")

    def setup_run(self, **kwargs: Any) -> dict[str, Any]:
        return self._as_dict("setup.run", kwargs)

    def cancel_job(self, job_id: str | None = None, *, force: bool = False) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if job_id is not None:
            params["job_id"] = job_id
        if force:
            params["force"] = True
        return self._as_dict("job.cancel", params)

    def clear_job(self) -> dict[str, Any]:
        return self._as_dict("job.clear")

    def job_status(self) -> dict[str, Any]:
        return self._as_dict("job.status")

    def rkhunter_scan(self) -> dict[str, Any]:
        return self._as_dict("rkhunter.scan")

    def rkhunter_update(self) -> dict[str, Any]:
        return self._as_dict("rkhunter.update")

    def rkhunter_propupd(self) -> dict[str, Any]:
        return self._as_dict("rkhunter.propupd")

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
        return self._as_dict("rkhunter.resolve", params)

    def history_list(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._as_list("history.list", {"limit": limit})

    def history_get(self, job_id: str) -> dict[str, Any]:
        return self._as_dict("history.get", {"job_id": job_id})

    def history_handle_open(
        self,
        job_id: str,
        *,
        quarantine: bool = False,
        resolve: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "history.handle_open",
            {
                "job_id": job_id,
                "quarantine": quarantine,
                "resolve": resolve,
                "force": force,
            },
        )

    def history_delete(self, job_id: str) -> dict[str, Any]:
        return self._as_dict("history.delete", {"job_id": job_id})

    def history_delete_all(self) -> dict[str, Any]:
        return self._as_dict("history.delete_all")

    def history_export(self, job_id: str, path: str, *, fmt: str = "json") -> dict[str, Any]:
        return self._as_dict(
            "history.export",
            {"job_id": job_id, "path": path, "format": fmt},
        )

    def history_export_all(
        self,
        path: str,
        *,
        fmt: str = "json",
        limit: int = 500,
    ) -> dict[str, Any]:
        return self._as_dict(
            "history.export_all",
            {"path": path, "format": fmt, "limit": limit},
        )

    def audit_list(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._as_list("audit.list", {"limit": limit})

    def quarantine_list(self) -> list[dict[str, Any]]:
        return self._as_list("quarantine.list")

    def quarantine_restore(self, entry_id: int) -> str:
        return str(self._call("quarantine.restore", {"id": entry_id}))

    def quarantine_delete(self, entry_id: int) -> None:
        self._call("quarantine.delete", {"id": entry_id})

    def quarantine_verify(self) -> dict[str, Any]:
        result = self._call("quarantine.verify")
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
        return self._as_dict("quarantine.add", params)

    def desktop_status(self) -> dict[str, Any]:
        return self._as_dict("desktop.status")

    def config_get(self, key: str | None = None) -> Any:
        params: dict[str, Any] = {}
        if key is not None:
            params["key"] = key
        return self._call("config.get", params)

    def config_set(self, key: str, value: str) -> None:
        self._call("config.set", {"key": key, "value": value})

    def schedule_install(self, profile: str = "quick") -> dict[str, Any]:
        return self._as_dict("schedule.install", {"profile": profile})

    def schedule_apply(self, *, smoke_test: bool = False) -> dict[str, Any]:
        return self._as_dict("schedule.apply", {"smoke_test": smoke_test})

    def schedule_status(self, profile: str = "quick") -> dict[str, Any]:
        _ = profile
        return self._as_dict("schedule.status", {})

    def schedule_run(self) -> dict[str, Any]:
        return self._as_dict("schedule.run", {})

    def linger_status(self) -> dict[str, Any]:
        return self._as_dict("schedule.linger")

    def linger_enable(self) -> dict[str, Any]:
        return self._as_dict("schedule.enable_linger")

    def runtime_status(self) -> dict[str, Any]:
        return self._as_dict("runtime.status")

    def runtime_update(self) -> dict[str, Any]:
        return self._as_dict("runtime.update")

    def maintenance_bootstrap(self, skip_lynis: bool = True) -> list[dict[str, object]]:
        return self._as_list("maintenance.bootstrap", {"skip_lynis": skip_lynis})

    def maintenance_post_update(self) -> list[dict[str, object]]:
        return self._as_list("maintenance.post-update")

    def firewall_status(self) -> dict[str, Any]:
        return self._as_dict("firewall.status")

    def fail2ban_unban(
        self,
        ip: str,
        *,
        jail: str | None = None,
        ignore: bool = False,
        persist: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "fail2ban.unban",
            {"ip": ip, "jail": jail, "ignore": ignore, "persist": persist},
        )

    def clamav_clamd_ensure(self) -> dict[str, Any]:
        return self._as_dict("clamav.clamd.ensure")

    def services_status(self) -> dict[str, Any]:
        return self._as_dict("services.status")

    def services_set(self, name: str, state: str, *, boot: bool = False) -> dict[str, Any]:
        return self._as_dict("services.set", {"name": name, "state": state, "boot": boot})

    def auth_status(self) -> dict[str, Any]:
        return self._as_dict("auth.status")

    def helper_install(self) -> dict[str, Any]:
        return self._as_dict("helper.install")

    def auth_grant_service_lifecycle(self, user: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if user is not None:
            params["user"] = user
        return self._as_dict("auth.grant_service_lifecycle", params)

    def auth_revoke_service_lifecycle(self) -> dict[str, Any]:
        return self._as_dict("auth.revoke_service_lifecycle")

    def clamonacc_status(self) -> dict[str, Any]:
        return self._as_dict("clamonacc.status")

    def clamonacc_start(self) -> dict[str, Any]:
        return self._as_dict("clamonacc.start")

    def clamonacc_stop(self) -> dict[str, Any]:
        return self._as_dict("clamonacc.stop")

    def clamonacc_enable(self) -> dict[str, Any]:
        return self._as_dict("clamonacc.enable")

    def clamonacc_disable(self) -> dict[str, Any]:
        return self._as_dict("clamonacc.disable")

    def clamonacc_add_path(self, path: str) -> None:
        self._call("clamonacc.add_path", {"path": path})

    def clamonacc_remove_path(self, path: str) -> None:
        self._call("clamonacc.remove_path", {"path": path})

    def news_list(
        self,
        *,
        force: bool = False,
        sources: list[str] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"force": force}
        if sources is not None:
            params["sources"] = sources
        return self._as_dict("news.list", params)

    def news_refresh(self, *, sources: list[str] | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if sources is not None:
            params["sources"] = sources
        return self._as_dict("news.refresh", params)

    def updates_check(self) -> dict[str, Any]:
        return self._as_dict("updates.check")

    def updates_apply(self) -> dict[str, Any]:
        return self._as_dict("updates.apply")
