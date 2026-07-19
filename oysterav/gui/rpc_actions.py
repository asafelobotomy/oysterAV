"""Thin OystClient call helpers used by GUI widgets.

Kept free of GTK imports so ADR-007 wiring can be unit-tested without PyGObject.
"""

from __future__ import annotations

from typing import Any, Protocol


class SupportsOystClient(Protocol):
    def cancel_job(self, job_id: str | None = None) -> dict[str, Any]: ...
    def job_status(self) -> dict[str, Any]: ...
    def quarantine_add(
        self,
        path: str,
        threat_name: str = "",
        *,
        job_id: str | None = None,
        pack: str = "",
        message: str = "",
    ) -> dict[str, Any]: ...
    def rkhunter_propupd(self) -> dict[str, Any]: ...
    def rkhunter_resolve(
        self,
        threat_name: str,
        *,
        path: str = "",
        message: str = "",
        force: bool = False,
        dry_run: bool = False,
        job_id: str | None = None,
    ) -> dict[str, Any]: ...
    def services_status(self) -> dict[str, Any]: ...
    def services_set(self, name: str, state: str, *, boot: bool = False) -> dict[str, Any]: ...
    def auth_status(self) -> dict[str, Any]: ...
    def helper_install(self) -> dict[str, Any]: ...
    def auth_grant_service_lifecycle(self, user: str | None = None) -> dict[str, Any]: ...
    def auth_revoke_service_lifecycle(self) -> dict[str, Any]: ...
    def firewall_status(self) -> dict[str, Any]: ...
    def fail2ban_unban(
        self,
        ip: str,
        *,
        jail: str | None = None,
        ignore: bool = False,
        persist: bool = False,
    ) -> dict[str, Any]: ...
    def audit_list(self, limit: int = 50) -> list[dict[str, Any]]: ...
    def history_list(self, limit: int = 20) -> list[dict[str, Any]]: ...
    def history_get(self, job_id: str) -> dict[str, Any]: ...
    def history_handle_open(
        self,
        job_id: str,
        *,
        quarantine: bool = False,
        resolve: bool = False,
        force: bool = False,
    ) -> dict[str, Any]: ...
    def history_delete(self, job_id: str) -> dict[str, Any]: ...
    def history_delete_all(self) -> dict[str, Any]: ...
    def history_export(
        self,
        job_id: str,
        path: str,
        *,
        fmt: str = "json",
    ) -> dict[str, Any]: ...
    def history_export_all(
        self,
        path: str,
        *,
        fmt: str = "json",
        limit: int = 500,
    ) -> dict[str, Any]: ...
    def news_refresh(self) -> dict[str, Any]: ...
    def updates_check(self) -> dict[str, Any]: ...
    def updates_apply(self) -> dict[str, Any]: ...
    def quarantine_list(self) -> list[dict[str, Any]]: ...


def request_job_cancel(
    client: SupportsOystClient,
    job_id: str | None = None,
) -> dict[str, Any]:
    return client.cancel_job(job_id)


def request_job_status(client: SupportsOystClient) -> dict[str, Any]:
    return client.job_status()


def request_quarantine_add(
    client: SupportsOystClient,
    path: str,
    threat_name: str = "",
    *,
    job_id: str | None = None,
    pack: str = "",
    message: str = "",
) -> dict[str, Any]:
    return client.quarantine_add(
        path,
        threat_name,
        job_id=job_id,
        pack=pack,
        message=message,
    )


def request_rkhunter_propupd(client: SupportsOystClient) -> dict[str, Any]:
    return client.rkhunter_propupd()


def request_rkhunter_resolve(
    client: SupportsOystClient,
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
    dry_run: bool = False,
    job_id: str | None = None,
) -> dict[str, Any]:
    return client.rkhunter_resolve(
        threat_name,
        path=path,
        message=message,
        dry_run=dry_run,
        job_id=job_id,
    )


def request_services_status(client: SupportsOystClient) -> dict[str, Any]:
    return client.services_status()


def request_services_set(
    client: SupportsOystClient,
    name: str,
    *,
    on: bool,
) -> dict[str, Any]:
    state = "on" if on else "off"
    return client.services_set(name, state, boot=on)


def request_auth_status(client: SupportsOystClient) -> dict[str, Any]:
    return client.auth_status()


def request_helper_install(client: SupportsOystClient) -> dict[str, Any]:
    return client.helper_install()


def request_auth_grant(client: SupportsOystClient, user: str | None = None) -> dict[str, Any]:
    return client.auth_grant_service_lifecycle(user)


def request_auth_revoke(client: SupportsOystClient) -> dict[str, Any]:
    return client.auth_revoke_service_lifecycle()


def request_firewall_status(client: SupportsOystClient) -> dict[str, Any]:
    return client.firewall_status()


def request_fail2ban_unban(
    client: SupportsOystClient,
    ip: str,
    *,
    jail: str | None = None,
) -> dict[str, Any]:
    return client.fail2ban_unban(ip, jail=jail)


def request_audit_list(client: SupportsOystClient, *, limit: int = 50) -> list[dict[str, Any]]:
    return client.audit_list(limit=limit)


def request_history_list(
    client: SupportsOystClient,
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    return client.history_list(limit=limit)


def request_history_get(client: SupportsOystClient, job_id: str) -> dict[str, Any]:
    return client.history_get(job_id)


def request_history_handle_open(
    client: SupportsOystClient,
    job_id: str,
    *,
    quarantine: bool = False,
    resolve: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    return client.history_handle_open(
        job_id,
        quarantine=quarantine,
        resolve=resolve,
        force=force,
    )


def request_history_delete(client: SupportsOystClient, job_id: str) -> dict[str, Any]:
    return client.history_delete(job_id)


def request_history_delete_all(client: SupportsOystClient) -> dict[str, Any]:
    return client.history_delete_all()


def request_history_export(
    client: SupportsOystClient,
    job_id: str,
    path: str,
    *,
    fmt: str = "json",
) -> dict[str, Any]:
    return client.history_export(job_id, path, fmt=fmt)


def request_history_export_all(
    client: SupportsOystClient,
    path: str,
    *,
    fmt: str = "json",
    limit: int = 500,
) -> dict[str, Any]:
    return client.history_export_all(path, fmt=fmt, limit=limit)


def request_news_refresh(client: SupportsOystClient) -> dict[str, Any]:
    return client.news_refresh()


def request_updates_check(client: SupportsOystClient) -> dict[str, Any]:
    return client.updates_check()


def request_updates_apply(client: SupportsOystClient) -> dict[str, Any]:
    return client.updates_apply()
