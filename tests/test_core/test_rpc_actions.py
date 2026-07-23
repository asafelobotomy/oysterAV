"""ADR-007 GUI → OystClient action helpers (no GTK)."""

from __future__ import annotations

from unittest.mock import MagicMock

from oysterav.gui.rpc_actions import (
    request_audit_list,
    request_auth_grant,
    request_auth_revoke,
    request_auth_status,
    request_fail2ban_unban,
    request_firewall_status,
    request_helper_install,
    request_history_get,
    request_history_list,
    request_job_cancel,
    request_job_status,
    request_news_refresh,
    request_quarantine_add,
    request_rkhunter_propupd,
    request_rkhunter_resolve,
    request_services_set,
    request_services_status,
    request_updates_apply,
    request_updates_check,
)


def test_request_job_cancel() -> None:
    client = MagicMock()
    client.cancel_job.return_value = {"ok": True, "cancelled": True}
    assert request_job_cancel(client)["cancelled"] is True
    client.cancel_job.assert_called_once_with(None)
    request_job_cancel(client, "abc")
    client.cancel_job.assert_called_with("abc")


def test_request_job_status() -> None:
    client = MagicMock()
    client.job_status.return_value = {"active": True, "pack": "clamav", "percent": 10.0}
    assert request_job_status(client)["pack"] == "clamav"
    client.job_status.assert_called_once_with()


def test_request_quarantine_add() -> None:
    client = MagicMock()
    client.quarantine_add.return_value = {"id": 1}
    assert request_quarantine_add(client, "/tmp/x", "t")["id"] == 1
    client.quarantine_add.assert_called_once_with(
        "/tmp/x",
        "t",
        job_id=None,
        pack="",
        message="",
    )
    request_quarantine_add(client, "/tmp/y", "t2", job_id="job1", pack="clamav", message="m")
    client.quarantine_add.assert_called_with(
        "/tmp/y",
        "t2",
        job_id="job1",
        pack="clamav",
        message="m",
    )


def test_request_rkhunter_propupd() -> None:
    client = MagicMock()
    client.rkhunter_propupd.return_value = {"ok": True, "message": "done"}
    assert request_rkhunter_propupd(client)["ok"] is True
    client.rkhunter_propupd.assert_called_once_with()


def test_request_rkhunter_resolve() -> None:
    client = MagicMock()
    client.rkhunter_resolve.return_value = {"ok": True, "option": "SCRIPTWHITELIST"}
    assert request_rkhunter_resolve(client, "rkhunter-hidden", path="/etc/.updated")["ok"] is True
    client.rkhunter_resolve.assert_called_once_with(
        "rkhunter-hidden",
        path="/etc/.updated",
        message="",
        dry_run=False,
        job_id=None,
    )


def test_request_services_set_maps_boot() -> None:
    client = MagicMock()
    client.services_set.return_value = {"ok": True}
    request_services_set(client, "fail2ban", on=True)
    client.services_set.assert_called_once_with("fail2ban", "on", boot=True)
    request_services_set(client, "fail2ban", on=False)
    client.services_set.assert_called_with("fail2ban", "off", boot=False)


def test_request_services_and_auth_status() -> None:
    client = MagicMock()
    client.services_status.return_value = {"names": ["clamd"]}
    client.auth_status.return_value = {"helper": {"installed": False}}
    assert request_services_status(client)["names"] == ["clamd"]
    assert request_auth_status(client)["helper"]["installed"] is False


def test_request_helper_install_and_auth_grant_revoke() -> None:
    client = MagicMock()
    client.helper_install.return_value = {"ok": True}
    client.auth_grant_service_lifecycle.return_value = {"ok": True}
    client.auth_revoke_service_lifecycle.return_value = {"ok": True}
    assert request_helper_install(client)["ok"] is True
    assert request_auth_grant(client, "alice")["ok"] is True
    client.auth_grant_service_lifecycle.assert_called_once_with("alice")
    assert request_auth_revoke(client)["ok"] is True
    client.auth_revoke_service_lifecycle.assert_called_once_with()


def test_request_host_security_actions() -> None:
    client = MagicMock()
    client.firewall_status.return_value = {"active": True}
    client.fail2ban_unban.return_value = {"ok": True}
    assert request_firewall_status(client)["active"] is True
    assert request_fail2ban_unban(client, "1.2.3.4", jail="sshd")["ok"] is True
    client.fail2ban_unban.assert_called_once_with("1.2.3.4", jail="sshd")


def test_request_audit_and_news() -> None:
    client = MagicMock()
    client.audit_list.return_value = [{"action": "x"}]
    client.news_refresh.return_value = {"ok": True}
    assert request_audit_list(client, limit=8) == [{"action": "x"}]
    client.audit_list.assert_called_once_with(limit=8)
    assert request_news_refresh(client)["ok"] is True


def test_request_history_list_and_get() -> None:
    client = MagicMock()
    client.history_list.return_value = [{"job_id": "a"}]
    client.history_get.return_value = {"job_id": "a", "clean": True}
    assert request_history_list(client, limit=10) == [{"job_id": "a"}]
    client.history_list.assert_called_once_with(limit=10)
    assert request_history_get(client, "a")["clean"] is True
    client.history_get.assert_called_once_with("a")


def test_request_history_handle_open() -> None:
    from oysterav.gui.rpc_actions import request_history_handle_open

    client = MagicMock()
    client.history_handle_open.return_value = {"ok": True, "quarantined": 2, "resolved": 0}
    assert request_history_handle_open(client, "job", quarantine=True)["quarantined"] == 2
    client.history_handle_open.assert_called_once_with(
        "job",
        quarantine=True,
        resolve=False,
        force=False,
    )


def test_request_history_delete_and_export() -> None:
    from oysterav.gui.rpc_actions import (
        request_history_delete,
        request_history_delete_all,
        request_history_export,
        request_history_export_all,
    )

    client = MagicMock()
    client.history_delete.return_value = {"ok": True, "deleted": 1}
    client.history_delete_all.return_value = {"ok": True, "deleted": 3}
    client.history_export.return_value = {"ok": True, "path": "/tmp/a.json"}
    client.history_export_all.return_value = {"ok": True, "count": 3}
    assert request_history_delete(client, "job")["deleted"] == 1
    assert request_history_delete_all(client)["deleted"] == 3
    assert request_history_export(client, "job", "/tmp/a.json", fmt="json")["ok"] is True
    client.history_export.assert_called_once_with("job", "/tmp/a.json", fmt="json")
    assert request_history_export_all(client, "/tmp/all.md", fmt="md")["count"] == 3
    client.history_export_all.assert_called_once_with("/tmp/all.md", fmt="md", limit=500)


def test_request_updates_check_and_apply() -> None:
    client = MagicMock()
    client.updates_check.return_value = {"ok": True, "updates": [], "message": ""}
    client.updates_apply.return_value = {"ok": True, "steps": []}
    assert request_updates_check(client)["ok"] is True
    client.updates_check.assert_called_once_with()
    assert request_updates_apply(client)["ok"] is True
    client.updates_apply.assert_called_once_with()
