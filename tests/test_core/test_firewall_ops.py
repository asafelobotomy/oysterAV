"""Tests for firewall ops safety guards."""

from __future__ import annotations

from unittest.mock import patch

from oyst_core.packs.firewall_ops import FirewallOps


def test_ufw_enable_blocked_without_ssh() -> None:
    ops = FirewallOps()
    with (
        patch.object(ops, "_active_backend", return_value="ufw"),
        patch.object(ops, "_ssh_allowed", return_value=False),
        patch.object(ops, "_snapshot", return_value="Status: inactive"),
        patch.object(ops._pack, "detect", return_value={"active": "ufw", "ufw": True}),
    ):
        result = ops.ufw_lifecycle("enable", dry_run=False, force_lockout=False)
    assert result.ok is False
    assert "SSH" in result.message


def test_ufw_enable_dry_run_allowed_without_ssh() -> None:
    ops = FirewallOps()
    with (
        patch.object(ops, "_active_backend", return_value="ufw"),
        patch.object(ops, "_ssh_allowed", return_value=False),
        patch.object(ops, "_snapshot", return_value=""),
        patch.object(ops._pack, "detect", return_value={"active": "ufw", "ufw": True}),
    ):
        result = ops.ufw_lifecycle("enable", dry_run=True)
    assert result.ok is True
    assert result.argv == ["ufw", "enable"]


def test_firewall_conflict_raises() -> None:
    ops = FirewallOps()
    with patch.object(ops._pack, "detect", return_value={"conflict": True, "active": "ufw"}):
        try:
            ops._active_backend()
        except ValueError as exc:
            assert "conflict" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError")


def test_ensure_firewall_enabled_skips_when_active() -> None:
    ops = FirewallOps()
    with patch.object(
        ops._pack,
        "detect",
        return_value={"conflict": False, "active": "ufw", "ufw": True},
    ):
        result = ops.ensure_firewall_enabled()
    assert result.ok is True
    assert result.skipped is True


def test_ensure_firewall_enabled_conflict() -> None:
    ops = FirewallOps()
    with patch.object(
        ops._pack,
        "detect",
        return_value={"conflict": True, "active": "ufw", "ufw": True, "firewalld": True},
    ):
        result = ops.ensure_firewall_enabled()
    assert result.ok is False
    assert "Multiple" in result.message or "conflict" in result.message.lower()


def test_ensure_firewall_enabled_inactive_ufw_uses_setup_harden() -> None:
    ops = FirewallOps()
    payload = {
        "steps": [{"step": "firewall-ensure", "ok": True, "message": "ufw enabled"}],
    }
    with (
        patch.object(
            ops._pack,
            "detect",
            return_value={
                "conflict": False,
                "active": "none",
                "ufw": True,
                "firewalld": False,
            },
        ),
        patch(
            "oyst_core.packs.firewall_ops.run_privileged_helper",
            return_value=type(
                "R",
                (),
                {"returncode": 0, "stdout": __import__("json").dumps(payload), "stderr": ""},
            )(),
        ) as helper,
    ):
        result = ops.ensure_firewall_enabled(force_lockout=False, dry_run=False)
    assert result.ok is True
    helper.assert_called_once()
    assert helper.call_args.args[0] == "setup-harden"
    assert "--with-firewall" in helper.call_args.args[1]


def test_ensure_firewall_enabled_no_backend_skips() -> None:
    ops = FirewallOps()
    with patch.object(
        ops._pack,
        "detect",
        return_value={
            "conflict": False,
            "active": "none",
            "ufw": False,
            "firewalld": False,
        },
    ):
        result = ops.ensure_firewall_enabled()
    assert result.ok is True
    assert result.skipped is True
