"""OystClient local-fallback coverage for ADR-007 surfaces."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from oyst_core.client import OystClient


def _client() -> OystClient:
    return OystClient(socket_path=Path("/nonexistent/oyst.sock"))


def test_client_cancel_job_local() -> None:
    client = _client()
    with patch.object(
        client._orchestrator,
        "cancel_job",
        return_value={"ok": True, "cancelled": True},
    ):
        assert client.cancel_job("j1")["cancelled"] is True


def test_client_services_and_auth_local() -> None:
    with patch(
        "oyst_core.services.services_status",
        return_value={"names": ["clamd"]},
    ):
        assert _client().services_status()["names"] == ["clamd"]
    with patch(
        "oyst_core.client.set_service",
        return_value={"ok": True},
    ):
        assert _client().services_set("clamd", "on", boot=True)["ok"] is True
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
        status = _client().auth_status()
    assert status["helper"]["installed"] is True


def test_client_audit_news_firewall_fail2ban_local() -> None:
    with patch(
        "oyst_core.audit.SecurityAudit.list_entries",
        return_value=[{"a": 1}],
    ):
        assert _client().audit_list(limit=3) == [{"a": 1}]
    with patch(
        "oyst_core.security_news.list_security_news",
        return_value={"items": []},
    ) as news:
        _client().news_list(force=False)
        _client().news_refresh()
        assert news.call_count == 2
    with patch(
        "oyst_core.updates.apply_all_updates",
        return_value={"ok": True, "steps": []},
    ):
        assert _client().updates_apply()["ok"] is True
    with patch(
        "oyst_core.packs.firewall.FirewallPack.status",
        return_value={"active": True},
    ):
        assert _client().firewall_status()["active"] is True
    with patch(
        "oyst_core.packs.fail2ban.Fail2banPack.unban",
        return_value=(True, "ok"),
    ):
        assert _client().fail2ban_unban("1.2.3.4", jail="sshd")["ok"] is True


def test_client_quarantine_add_and_maintenance_local() -> None:
    entry = MagicMock()
    entry.model_dump.return_value = {"id": 9}
    with patch("oyst_core.history_actions.QuarantineVault") as vault:
        vault.return_value.add.return_value = entry
        assert _client().quarantine_add("/tmp/x", "t")["id"] == 9
    with patch(
        "oyst_core.maintenance.run_bootstrap",
        return_value=[{"step": "x", "ok": True}],
    ):
        assert _client().maintenance_bootstrap(skip_lynis=True)[0]["step"] == "x"
    with patch(
        "oyst_core.maintenance.run_post_update",
        return_value=[{"step": "y", "ok": True}],
    ):
        assert _client().maintenance_post_update()[0]["step"] == "y"


def test_client_desktop_status_local() -> None:
    with patch(
        "oyst_core.desktop_util.autostart_status",
        return_value={"enabled": False},
    ):
        assert _client().desktop_status()["enabled"] is False
