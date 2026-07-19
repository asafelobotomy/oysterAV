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
