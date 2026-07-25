"""Tests for firewall ops safety guards."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from oyst_core.packs.firewall_ops import FirewallOps, FirewallResult
from oyst_core.privileged.validators import validate_rich_rule


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


def test_parse_ssh_open_ignores_deny() -> None:
    assert FirewallOps.parse_ssh_open("22/tcp DENY IN Anywhere") is False
    assert FirewallOps.parse_ssh_open("22/tcp ALLOW IN Anywhere") is True
    assert FirewallOps.parse_ssh_open("22/tcp LIMIT IN Anywhere") is True
    assert FirewallOps.parse_ssh_open("Status: inactive") is False


def test_ufw_delete_22_blocked_without_force() -> None:
    ops = FirewallOps()
    with patch.object(ops, "_active_backend", return_value="ufw"):
        result = ops.ufw_rule("delete", port="22", force_lockout=False)
    assert result.ok is False
    assert "force-lockout" in result.message


def test_ufw_delete_22_allowed_with_force() -> None:
    ops = FirewallOps()
    with (
        patch.object(ops, "_active_backend", return_value="ufw"),
        patch.object(ops, "_run", return_value=FirewallResult(ok=True, message="ok")) as run,
    ):
        result = ops.ufw_rule("delete", port="22", force_lockout=True)
    assert result.ok is True
    run.assert_called_once()


def test_validate_rich_rule_subset() -> None:
    assert validate_rich_rule("rule family=ipv4 port port=22 protocol=tcp accept")
    assert validate_rich_rule("rule service name=ssh drop")
    try:
        validate_rich_rule("rule family=ipv4 accept")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        validate_rich_rule("rule port port=22 protocol=tcp accept; rm -rf /")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_ensure_firewall_enabled_skips_when_active() -> None:
    with patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls:
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "ufw",
            "ufw": True,
        }
        result = FirewallOps().ensure_firewall_enabled()
    assert result.ok is True
    assert result.skipped is True


def test_ensure_firewall_enabled_conflict() -> None:
    with patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls:
        pack_cls.return_value.detect.return_value = {
            "conflict": True,
            "active": "ufw",
            "ufw": True,
            "firewalld": True,
        }
        result = FirewallOps().ensure_firewall_enabled()
    assert result.ok is False


def test_ensure_firewall_enabled_inactive_uses_select() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ufw enabled"),
        ) as sel,
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="ufw",
        ),
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": False,
        }
        result = FirewallOps().ensure_firewall_enabled(force_lockout=False, dry_run=False)
    assert result.ok is True
    sel.assert_called_once()
    assert sel.call_args.args[0] == "ufw"


def test_ensure_honors_managed_backend_preference() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value="firewalld"),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ok"),
        ) as sel,
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": True,
        }
        FirewallOps().ensure_firewall_enabled()
    assert sel.call_args.args[0] == "firewalld"


def test_ensure_firewall_enabled_no_backend_skips() -> None:
    with patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls:
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": False,
            "firewalld": False,
        }
        result = FirewallOps().ensure_firewall_enabled()
    assert result.ok is True
    assert result.skipped is True


def test_set_managed_enabled_on_delegates() -> None:
    with patch(
        "oyst_core.packs.firewall_ensure.ensure_firewall_enabled",
        return_value=FirewallResult(ok=True, message="ok"),
    ) as mock:
        result = FirewallOps().set_managed_enabled(True)
    assert result.ok is True
    mock.assert_called_once()


def test_set_managed_enabled_off_ufw() -> None:
    ops_inst = MagicMock()
    ops_inst._pack.detect.return_value = {"conflict": False, "active": "ufw"}
    ops_inst.ufw_lifecycle.return_value = FirewallResult(ok=True, message="disabled")
    with patch("oyst_core.packs.firewall_ensure.FirewallOps", return_value=ops_inst):
        result = FirewallOps().set_managed_enabled(False)
    assert result.ok is True
    ops_inst.ufw_lifecycle.assert_called_once_with("disable", dry_run=False)


def test_set_managed_enabled_off_firewalld() -> None:
    ops_inst = MagicMock()
    ops_inst._pack.detect.return_value = {"conflict": False, "active": "firewalld"}
    ops_inst.firewalld_lifecycle.return_value = FirewallResult(ok=True, message="stopped")
    with patch("oyst_core.packs.firewall_ensure.FirewallOps", return_value=ops_inst):
        result = FirewallOps().set_managed_enabled(False)
    assert result.ok is True
    ops_inst.firewalld_lifecycle.assert_called_once_with("disable", dry_run=False)


def test_set_managed_enabled_off_nft_skips() -> None:
    ops_inst = MagicMock()
    ops_inst._pack.detect.return_value = {"conflict": False, "active": "nft-direct"}
    with patch("oyst_core.packs.firewall_ensure.FirewallOps", return_value=ops_inst):
        result = FirewallOps().set_managed_enabled(False)
    assert result.ok is True
    assert result.skipped is True


def test_recommended_managed_backend_arch_ufw() -> None:
    from oyst_core.packs import firewall_select

    with patch("oyst_core.packs.firewall_select.detect_distro_family", return_value="arch"):
        assert firewall_select.recommended_managed_backend() == "ufw"


def test_select_managed_backend_dry_run() -> None:
    from oyst_core.packs import firewall_select

    with patch("oyst_core.packs.firewall_select.which", return_value="/usr/bin/ufw"):
        result = firewall_select.select_managed_backend("ufw", dry_run=True)
    assert result.ok is True
    assert result.message == "dry-run"
    assert "--select-firewall=ufw" in (result.argv or [])


def test_select_managed_backend_missing_binary_uses_install_flag() -> None:
    from oyst_core.packs import firewall_select
    from oyst_core.privileged.runner import CommandResult

    with (
        patch("oyst_core.packs.firewall_select.which", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.run_privileged_helper",
            return_value=CommandResult(
                1,
                json.dumps(
                    {
                        "steps": [
                            {
                                "step": "firewall-install",
                                "ok": False,
                                "message": "pacman failed",
                            },
                        ],
                    },
                ),
                "",
            ),
        ) as helper,
    ):
        result = firewall_select.select_managed_backend("firewalld")
    assert result.ok is False
    assert "pacman failed" in result.message
    argv = helper.call_args.args[1]
    assert "--install-firewall=firewalld" in argv
    assert "--select-firewall=firewalld" in argv


def test_select_managed_backend_dry_run_would_install() -> None:
    from oyst_core.packs import firewall_select

    with patch("oyst_core.packs.firewall_select.which", return_value=None):
        result = firewall_select.select_managed_backend("ufw", dry_run=True)
    assert result.ok is True
    assert "would install ufw" in result.message
    assert "--install-firewall=ufw" in (result.argv or [])


def test_select_managed_backend_installs_then_selects() -> None:
    from oyst_core.packs import firewall_select
    from oyst_core.privileged.runner import CommandResult

    with (
        patch("oyst_core.packs.firewall_select.which", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.run_privileged_helper",
            return_value=CommandResult(
                0,
                json.dumps(
                    {
                        "steps": [
                            {"step": "firewall-install", "ok": True, "message": "ok"},
                            {
                                "step": "firewall-select",
                                "ok": True,
                                "message": "selected",
                            },
                        ],
                    },
                ),
                "",
            ),
        ) as helper,
    ):
        result = firewall_select.select_managed_backend("firewalld")
    assert result.ok is True
    assert "selected" in result.message
    assert "--install-firewall=firewalld" in helper.call_args.args[1]


def test_detect_nft_binary_alone_is_none() -> None:
    from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache

    invalidate_firewall_detect_cache()
    pack = FirewallPack()

    def fake_which(name: str) -> str | None:
        mapping = {
            "ufw": "/usr/bin/ufw",
            "firewall-cmd": "/usr/bin/firewall-cmd",
            "nft": "/usr/bin/nft",
        }
        return mapping.get(name)

    def fake_run(argv: list[str], timeout: int = 30) -> MagicMock:  # noqa: ARG001
        cmd = " ".join(argv)
        out = ""
        if "ufw" in cmd and "status" in cmd:
            out = "Status: inactive"
        elif "firewall-cmd" in cmd and "--state" in cmd:
            out = "not running"
        elif "nft" in cmd:
            out = ""
        return MagicMock(returncode=0, stdout=out, stderr="")

    with (
        patch("oyst_core.packs.firewall.which", side_effect=fake_which),
        patch("oyst_core.packs.firewall.run_command", side_effect=fake_run),
        patch.object(FirewallPack, "_tool_version", return_value=None),
    ):
        det = pack.detect()
    assert det["active"] == "none"
    assert det["nft"] is True
    assert det["ufw"] is True


def test_detect_nft_rules_sets_nft_direct() -> None:
    from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache

    invalidate_firewall_detect_cache()
    pack = FirewallPack()
    with (
        patch("oyst_core.packs.firewall.which") as which_mock,
        patch.object(FirewallPack, "_nft_filtering_active", return_value=True),
        patch.object(FirewallPack, "_tool_version", return_value="1.0"),
        patch(
            "oyst_core.packs.firewall.run_command",
            return_value=MagicMock(returncode=0, stdout="inactive", stderr=""),
        ),
    ):

        def _which(name: str) -> str | None:
            if name == "nft":
                return "/usr/bin/nft"
            return None

        which_mock.side_effect = _which
        det = pack.detect()
    assert det["active"] == "nft-direct"


def test_doctor_installed_with_inactive_ufw() -> None:
    from oyst_core.packs.firewall import FirewallPack

    pack = FirewallPack()
    with patch.object(
        pack,
        "detect",
        return_value={
            "active": "none",
            "ufw": True,
            "firewalld": False,
            "version": "",
            "conflict": False,
        },
    ):
        status = pack.doctor()
    assert status.installed is True
