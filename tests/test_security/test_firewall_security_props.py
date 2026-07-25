"""Firewall security-property regressions (FW remediations)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ensure import ensure_firewall_enabled
from oyst_core.packs.firewall_ops import FirewallOps, FirewallResult
from oyst_core.packs.firewall_select import select_managed_backend
from oyst_core.rpc_handlers.shield_fw import _fw_dict

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("22/tcp DENY IN Anywhere", False),
        ("22/tcp REJECT IN Anywhere", False),
        ("22 DROP", False),
        ("22/tcp ALLOW IN Anywhere", True),
        ("22/tcp LIMIT IN Anywhere", True),
        ("services: ssh dhcpv6-client", False),  # no allow/accept verb
        ("rule family=ipv4 service name=ssh accept", True),
    ],
)
def test_parse_ssh_open_deny_vs_allow(text: str, expected: bool) -> None:
    assert FirewallOps.parse_ssh_open(text) is expected


def test_ufw_rule_delete_deny_22_requires_force() -> None:
    ops = FirewallOps()
    with patch.object(ops, "_active_backend", return_value="ufw"):
        delete = ops.ufw_rule("delete", port="22", force_lockout=False)
        deny = ops.ufw_rule("deny", port="22", force_lockout=False)
    assert delete.ok is False
    assert deny.ok is False
    assert "force-lockout" in delete.message


def test_select_managed_backend_dry_run_includes_install_when_missing() -> None:
    with patch("oyst_core.packs.firewall_select.which", return_value=None):
        result = select_managed_backend("ufw", dry_run=True)
    assert result.ok is True
    assert result.argv is not None
    assert any(a.startswith("--install-firewall=") for a in result.argv)
    assert any(a.startswith("--select-firewall=") for a in result.argv)


def test_select_managed_backend_live_single_setup_harden() -> None:
    helper = MagicMock()
    helper.return_value = MagicMock(
        returncode=0,
        stdout='{"steps":[{"step":"firewall-select","ok":true,"message":"ok"}]}',
        stderr="",
    )
    with (
        patch("oyst_core.packs.firewall_select.which", return_value="/usr/bin/ufw"),
        patch("oyst_core.packs.firewall_select.run_privileged_helper", helper),
        patch(
            "oyst_core.packs.firewall_select.parse_helper_steps",
            return_value=[{"step": "firewall-select", "ok": True, "message": "ok"}],
        ),
    ):
        result = select_managed_backend("ufw", dry_run=False)
    assert result.ok is True
    helper.assert_called_once()
    assert helper.call_args.args[0] == "setup-harden"
    # Must not fall back to a separate package-install privilege path.
    assert "run_privileged_install" not in str(helper.call_args)


def test_fw_dict_omits_before_after() -> None:
    raw = FirewallResult(
        ok=True,
        message="ok",
        argv=["ufw", "allow"],
        before="SECRET RULE DUMP",
        after="MORE SECRETS",
    )
    out = _fw_dict(raw)
    assert "before" not in out
    assert "after" not in out
    assert out["ok"] is True


def test_detect_inactive_ufw_plus_nft_binary_is_none() -> None:
    invalidate_firewall_detect_cache()
    pack = FirewallPack()
    with (
        patch(
            "oyst_core.packs.firewall.which",
            side_effect=lambda b: f"/usr/bin/{b}" if b in {"ufw", "nft"} else None,
        ),
        patch(
            "oyst_core.packs.firewall.run_command",
            side_effect=lambda argv, timeout=30: MagicMock(
                stdout=(
                    "Status: inactive"
                    if argv[:2] == ["ufw", "status"]
                    else "table inet filter {}\n"
                ),
                stderr="",
                returncode=0,
            ),
        ),
        patch.object(FirewallPack, "_nft_filtering_active", return_value=False),
    ):
        det = pack._detect_uncached()
    assert det["active"] == "none"
    assert det["ufw"] is True
    assert det["nft"] is True


def test_detect_nft_ruleset_with_drop_is_nft_direct() -> None:
    invalidate_firewall_detect_cache()
    pack = FirewallPack()
    with (
        patch(
            "oyst_core.packs.firewall.which",
            side_effect=lambda b: "/usr/sbin/nft" if b == "nft" else None,
        ),
        patch.object(FirewallPack, "_nft_filtering_active", return_value=True),
        patch.object(FirewallPack, "_tool_version", return_value="1.0.0"),
    ):
        det = pack._detect_uncached()
    assert det["active"] == "nft-direct"


def test_ensure_explicit_none_skips() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value="none"),
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": False,
        }
        result = ensure_firewall_enabled()
    assert result.ok is True
    assert result.skipped is True
    assert "none" in result.message.lower()


def test_ensure_string_none_does_not_skip() -> None:
    """Config default serializes as 'None' — must not be treated as skip."""
    select = MagicMock(return_value=FirewallResult(ok=True, message="selected"))
    with (
        patch(
            "oyst_core.packs.firewall_ensure.FirewallPack",
        ) as pack_cls,
        patch(
            "oyst_core.config_access.get_config_value",
            return_value="None",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            select,
        ),
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="ufw",
        ),
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": True,
        }
        result = ensure_firewall_enabled()
    assert result.ok is True
    select.assert_called_once()
    assert select.call_args.args[0] == "ufw"


def test_ensure_preferred_backend_when_both_installed() -> None:
    select = MagicMock(return_value=FirewallResult(ok=True, message="ok"))
    with (
        patch(
            "oyst_core.packs.firewall_ensure.FirewallPack",
        ) as pack_cls,
        patch(
            "oyst_core.config_access.get_config_value",
            return_value="firewalld",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            select,
        ),
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": True,
        }
        ensure_firewall_enabled()
    select.assert_called_once()
    assert select.call_args.args[0] == "firewalld"
