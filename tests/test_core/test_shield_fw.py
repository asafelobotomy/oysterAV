"""Tests for Shield RPC handlers (firewall + fail2ban)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.firewall_ops import FirewallResult
from oyst_core.rpc_errors import RpcValidationError
from oyst_core.rpc_handlers import shield_fw


def test_firewall_ensure_enable() -> None:
    with patch("oyst_core.packs.firewall_ops.FirewallOps.ensure_firewall_enabled") as mock:
        mock.return_value = FirewallResult(
            ok=True,
            skipped=True,
            message="already active",
            before="secret",
            after="secret2",
        )
        out = shield_fw.handle_firewall_ensure_enable({}, MagicMock())
    assert out["ok"] is True
    assert out["skipped"] is True
    assert "before" not in out
    assert "after" not in out


def test_firewall_set_enabled() -> None:
    with patch("oyst_core.packs.firewall_ops.FirewallOps.set_managed_enabled") as mock:
        mock.return_value = FirewallResult(ok=True, message="ok")
        out = shield_fw.handle_firewall_set_enabled({"enabled": False}, MagicMock())
    assert out["ok"] is True
    mock.assert_called_once()
    with pytest.raises(RpcValidationError):
        shield_fw.handle_firewall_set_enabled({}, MagicMock())


def test_firewall_firewalld_rich_rule() -> None:
    with patch("oyst_core.packs.firewall_ops.FirewallOps.firewalld_rich_rule") as mock:
        mock.return_value = FirewallResult(ok=True, message="ok")
        out = shield_fw.handle_firewall_firewalld_rich_rule(
            {"action": "add", "rule": "rule family=ipv4 port port=22 protocol=tcp accept"},
            MagicMock(),
        )
    assert out["ok"] is True
    mock.assert_called_once()
    with pytest.raises(RpcValidationError):
        shield_fw.handle_firewall_firewalld_rich_rule({"action": "add"}, MagicMock())


def test_firewall_select_and_recommend() -> None:
    with patch("oyst_core.packs.firewall_select.select_managed_backend") as mock:
        mock.return_value = FirewallResult(ok=True, message="ufw enabled")
        out = shield_fw.handle_firewall_select({"backend": "ufw"}, MagicMock())
    assert out["ok"] is True
    with pytest.raises(RpcValidationError):
        shield_fw.handle_firewall_select({"backend": "iptables"}, MagicMock())
    with patch("oyst_core.packs.firewall.FirewallPack.detect") as det:
        det.return_value = {"active": "none"}
        with patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="ufw",
        ):
            rec = shield_fw.handle_firewall_recommend({}, MagicMock())
    assert rec["recommended"] == "ufw"


def test_firewall_ufw_rule_validation() -> None:
    with pytest.raises(RpcValidationError):
        shield_fw.handle_firewall_ufw_rule({"action": "bogus"}, MagicMock())


def test_firewall_ufw_rule_ok() -> None:
    with patch("oyst_core.packs.firewall_ops.FirewallOps.ufw_rule") as mock:
        mock.return_value = FirewallResult(ok=True, message="ok")
        out = shield_fw.handle_firewall_ufw_rule(
            {"action": "allow", "port": "22", "proto": "tcp"},
            MagicMock(),
        )
    assert out["ok"] is True
    mock.assert_called_once()


def test_fail2ban_status_and_reload() -> None:
    with patch("oyst_core.packs.fail2ban.Fail2banPack.service_status") as mock:
        mock.return_value = {"installed": True, "running": True, "jails": ["sshd"]}
        assert shield_fw.handle_fail2ban_status({}, MagicMock())["jails"] == ["sshd"]
    with patch("oyst_core.packs.fail2ban.Fail2banPack.reload") as mock:
        mock.return_value = (True, "ok")
        out = shield_fw.handle_fail2ban_reload({"unban": True}, MagicMock())
    assert out == {"ok": True, "message": "ok", "unban": True}


def test_request_shield_rpc_actions() -> None:
    from oysterav.gui.rpc_actions_shield import (
        request_fail2ban_reload,
        request_firewall_ensure_enable,
        request_firewall_firewalld_rich_rule,
        request_firewall_set_enabled,
        request_firewall_ufw_rule,
    )

    client = MagicMock()
    client.firewall_ensure_enable.return_value = {"ok": True}
    client.firewall_set_enabled.return_value = {"ok": True}
    client.firewall_ufw_rule.return_value = {"ok": True}
    client.firewall_firewalld_rich_rule.return_value = {"ok": True}
    client.fail2ban_reload.return_value = {"ok": True}
    assert request_firewall_ensure_enable(client)["ok"] is True
    assert request_firewall_set_enabled(client, False)["ok"] is True
    assert request_firewall_ufw_rule(client, "allow", port="80")["ok"] is True
    assert (
        request_firewall_firewalld_rich_rule(client, "add", "rule family=ipv4 accept")["ok"] is True
    )
    assert request_fail2ban_reload(client, unban=True)["ok"] is True
