"""Behavioral tests for high-risk RpcServer._dispatch methods."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.rpc_auth import ensure_rpc_token
from oyst_core.serve import RpcServer


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RpcServer:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    return RpcServer(tmp_path / "rpc.sock")


def _call(server: RpcServer, method: str, params: dict | None = None) -> dict:
    token = ensure_rpc_token()
    return server.handle(
        {"method": method, "params": params or {}, "id": 1, "auth": token},
    )


def test_rpc_job_cancel(server: RpcServer) -> None:
    with patch.object(
        server.orchestrator,
        "cancel_job",
        return_value={"ok": True, "cancelled": True, "job_id": "j1"},
    ) as cancel:
        resp = _call(server, "job.cancel", {"job_id": "j1"})
    assert resp["result"]["cancelled"] is True
    cancel.assert_called_once_with("j1")


def test_rpc_services_set(server: RpcServer) -> None:
    with patch(
        "oyst_core.services.set_service",
        return_value={"ok": True, "name": "fail2ban", "state": "on"},
    ) as setter:
        resp = _call(
            server,
            "services.set",
            {"name": "fail2ban", "state": "on", "boot": True},
        )
    assert resp["result"]["ok"] is True
    setter.assert_called_once_with("fail2ban", "on", boot=True)


def test_rpc_services_set_unknown_validation(server: RpcServer) -> None:
    resp = _call(server, "services.set", {"name": "nginx", "state": "on"})
    assert resp["error"]["code"] == "validation_error"


def test_rpc_quarantine_delete(server: RpcServer) -> None:
    with patch("oyst_core.serve.QuarantineVault") as vault_cls:
        vault_cls.return_value.delete = MagicMock()
        resp = _call(server, "quarantine.delete", {"id": 7})
    assert resp["result"] is True
    vault_cls.return_value.delete.assert_called_once_with(7)


def test_rpc_quarantine_add(server: RpcServer) -> None:
    entry = MagicMock()
    entry.model_dump.return_value = {"id": 1, "threat_name": "x"}
    with (
        patch("oyst_core.history_actions.QuarantineVault") as vault_cls,
        patch("oyst_core.serve.SecurityAudit") as audit_cls,
    ):
        vault_cls.return_value.add.return_value = entry
        audit_cls.return_value.log = MagicMock()
        resp = _call(
            server,
            "quarantine.add",
            {"path": "/tmp/x", "threat_name": "x"},
        )
    assert resp["result"]["id"] == 1


def test_rpc_fail2ban_unban(server: RpcServer) -> None:
    with (
        patch("oyst_core.packs.fail2ban.Fail2banPack.unban", return_value=(True, "ok")),
        patch("oyst_core.serve.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        resp = _call(server, "fail2ban.unban", {"ip": "1.2.3.4", "jail": "sshd"})
    assert resp["result"]["ok"] is True


def test_rpc_clamonacc_enable_disable(server: RpcServer) -> None:
    with (
        patch("oyst_core.packs.clamonacc.ClamonaccPack.enable", return_value=(True, "on")),
        patch("oyst_core.serve.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        resp = _call(server, "clamonacc.enable")
    assert resp["result"]["ok"] is True

    with (
        patch("oyst_core.packs.clamonacc.ClamonaccPack.disable", return_value=(True, "off")),
        patch("oyst_core.serve.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        resp = _call(server, "clamonacc.disable")
    assert resp["result"]["ok"] is True


def test_rpc_clamonacc_paths(server: RpcServer) -> None:
    with patch("oyst_core.packs.clamonacc.ClamonaccPack.add_path") as add:
        resp = _call(server, "clamonacc.add_path", {"path": "/home/u/Downloads"})
    assert resp["result"] is True
    add.assert_called_once_with("/home/u/Downloads")

    with patch("oyst_core.packs.clamonacc.ClamonaccPack.remove_path") as rem:
        resp = _call(server, "clamonacc.remove_path", {"path": "/home/u/Downloads"})
    assert resp["result"] is True
    rem.assert_called_once_with("/home/u/Downloads")


def test_rpc_services_status(server: RpcServer) -> None:
    fake = {"services": {}, "names": ["clamd"]}
    with patch("oyst_core.services.services_status", return_value=fake):
        resp = _call(server, "services.status")
    assert resp["result"]["names"] == ["clamd"]


def test_rpc_auth_status(server: RpcServer) -> None:
    with (
        patch(
            "oyst_core.privileged.install_privileged_helper.helper_status",
            return_value={"installed": True},
        ),
        patch(
            "oyst_core.privileged.auth_grant.auth_status",
            return_value={"granted": False},
        ),
    ):
        resp = _call(server, "auth.status")
    assert resp["result"]["helper"]["installed"] is True


def test_rpc_helper_install(server: RpcServer) -> None:
    with patch(
        "oyst_core.privileged.elevate_cli.install_helper_elevated",
        return_value={"ok": True, "message": "Installed"},
    ):
        resp = _call(server, "helper.install")
    assert resp["result"]["ok"] is True


def test_rpc_auth_grant_revoke(server: RpcServer) -> None:
    with patch(
        "oyst_core.privileged.elevate_cli.grant_service_lifecycle_elevated",
        return_value={"ok": True, "granted_user": "u"},
    ) as grant:
        resp = _call(server, "auth.grant_service_lifecycle", {"user": "u"})
    assert resp["result"]["ok"] is True
    grant.assert_called_once_with("u")
    with patch(
        "oyst_core.privileged.elevate_cli.revoke_service_lifecycle_elevated",
        return_value={"ok": True},
    ):
        resp = _call(server, "auth.revoke_service_lifecycle")
    assert resp["result"]["ok"] is True


def test_rpc_audit_list(server: RpcServer) -> None:
    with patch(
        "oyst_core.serve.SecurityAudit.list_entries",
        return_value=[{"action": "x"}],
    ):
        resp = _call(server, "audit.list", {"limit": 5})
    assert resp["result"] == [{"action": "x"}]


def test_rpc_news_refresh(server: RpcServer) -> None:
    with patch(
        "oyst_core.security_news.list_security_news",
        return_value={"ok": True, "items": []},
    ) as news:
        resp = _call(server, "news.refresh")
    assert resp["result"]["ok"] is True
    news.assert_called_once_with(force_refresh=True, sources=None)


def test_rpc_updates_apply(server: RpcServer) -> None:
    with patch(
        "oyst_core.updates.apply_all_updates",
        return_value={"ok": True, "steps": [{"step": "packages", "ok": True, "skipped": True}]},
    ):
        resp = _call(server, "updates.apply")
    assert resp["result"]["ok"] is True
    assert resp["result"]["steps"][0]["step"] == "packages"


def test_rpc_firewall_status(server: RpcServer) -> None:
    with patch(
        "oyst_core.packs.firewall.FirewallPack.status",
        return_value={"backend": "ufw", "active": True},
    ):
        resp = _call(server, "firewall.status")
    assert resp["result"]["backend"] == "ufw"


def test_rpc_maintenance_bootstrap(server: RpcServer) -> None:
    with patch(
        "oyst_core.maintenance.run_bootstrap",
        return_value=[{"step": "freshclam", "ok": True}],
    ):
        resp = _call(server, "maintenance.bootstrap", {"skip_lynis": True})
    assert resp["result"][0]["step"] == "freshclam"
