"""Extra coverage for choosing, installing and turning on a firewall (@pytest.mark.security)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oyst_core.packs.firewall_ensure import ensure_firewall_enabled
from oyst_core.packs.firewall_ops import FirewallResult
from oyst_core.packs.firewall_select import recommended_managed_backend, select_managed_backend
from oyst_core.privileged import helper_fw_lifecycle as life

pytestmark = pytest.mark.security


# --- validators leftovers ---


def test_ensure_as_root_skips_when_active() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"conflict": False, "active": "ufw", "ufw": True},
        ),
    ):
        step = life.ensure_firewall_as_root()
    assert step.get("skipped") is True


def test_ensure_as_root_conflict_and_none() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"conflict": True, "active": "ufw"},
        ),
    ):
        assert life.ensure_firewall_as_root()["ok"] is False
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "conflict": False,
                "active": "none",
                "ufw": False,
                "firewalld": False,
            },
        ),
    ):
        assert life.ensure_firewall_as_root().get("skipped") is True


def test_ensure_as_root_delegates_firewalld() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "conflict": False,
                "active": "none",
                "ufw": False,
                "firewalld": True,
            },
        ),
        patch.object(
            life,
            "_ensure_firewalld",
            return_value={"step": "firewall-ensure", "ok": True},
        ) as ens,
    ):
        life.ensure_firewall_as_root()
    ens.assert_called_once()


def test_select_none_and_missing_backends() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw_active": True,
                "active": "ufw",
                "firewalld_active": False,
                "conflict": False,
            },
        ),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
    ):
        step = life.select_firewall_as_root("none")
    assert step["ok"] is True
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"ufw": False, "firewalld": False},
        ),
    ):
        assert life.select_firewall_as_root("ufw")["ok"] is False
        assert life.select_firewall_as_root("firewalld")["ok"] is False
    assert life.select_firewall_as_root("bogus")["ok"] is False


def test_family_install_argv_variants() -> None:
    assert "dnf" in life._family_install_argv("fedora", ["ufw"])[0]
    assert "apt-get" in life._family_install_argv("debian", ["ufw"])[0]
    with pytest.raises(ValueError):
        life._family_install_argv("unknown", ["ufw"])
    with pytest.raises(ValueError):
        life._family_install_argv("arch", [])


def test_apply_with_firewall_flag() -> None:
    with patch.object(
        life,
        "ensure_firewall_as_root",
        return_value={"step": "firewall-ensure", "ok": True},
    ) as ens:
        steps = life.apply_firewall_lifecycle_flags(["--with-firewall"])
    assert steps[0]["ok"] is True
    ens.assert_called_once()


def test_install_invalid_backend() -> None:
    step = life.install_firewall_package_as_root("nft")
    assert step["ok"] is False


def test_recommended_backend_fedora() -> None:
    with patch("oyst_core.packs.firewall_select.detect_distro_family", return_value="fedora"):
        assert recommended_managed_backend() == "firewalld"


def test_select_invalid_backend() -> None:
    assert select_managed_backend("iptables").ok is False


def test_ensure_rec_firewalld_when_only_fw() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="firewalld",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ok"),
        ) as sel,
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": False,
            "firewalld": True,
        }
        ensure_firewall_enabled()
    assert sel.call_args.args[0] == "firewalld"


def test_select_none_stops_firewalld() -> None:
    calls: list[list[str]] = []

    def _run(cmd: list[str]) -> tuple[int, str]:
        calls.append(cmd)
        return 0, "ok"

    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(life, "_run_cmd", side_effect=_run),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw_active": False,
                "firewalld_active": True,
                "active": "firewalld",
                "conflict": False,
            },
        ),
    ):
        step = life.select_firewall_as_root("none")
    assert step["ok"] is True
    assert any(c[:3] == ["systemctl", "stop", "firewalld"] for c in calls)


def test_select_to_firewalld_disables_ufw() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(
            life.FirewallPack,
            "detect",
            side_effect=[
                {
                    "ufw": True,
                    "firewalld": True,
                    "ufw_active": True,
                    "firewalld_active": False,
                    "conflict": False,
                    "active": "ufw",
                },
                {"ufw": True, "firewalld": True, "conflict": False, "active": "none"},
            ],
        ),
        patch.object(
            life,
            "_ensure_firewalld",
            return_value={"step": "firewall-ensure", "ok": True, "message": "ok"},
        ),
    ):
        step = life.select_firewall_as_root("firewalld")
    assert step["ok"] is True


def test_ensure_ufw_force_lockout_skips_ssh_check() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_fw_enable.ufw_status_text",
            return_value="Status: inactive",
        ),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_ufw(force_lockout=True)
    assert step["ok"] is True


def test_ensure_firewalld_force_lockout() -> None:
    with (
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_firewalld(force_lockout=True)
    assert step["ok"] is True


def test_select_already_active_skips() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw": True,
                "firewalld": False,
                "ufw_active": True,
                "firewalld_active": False,
                "conflict": False,
                "active": "ufw",
            },
        ),
    ):
        step = life.select_firewall_as_root("ufw")
    assert step.get("skipped") is True


def test_select_managed_force_lockout_flag() -> None:
    with patch("oyst_core.packs.firewall_select.which", return_value="/usr/bin/ufw"):
        result = select_managed_backend("ufw", dry_run=True, force_lockout=True)
    assert "--force-lockout" in (result.argv or [])


def test_ensure_prefer_ufw_when_rec_fw_missing() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="firewalld",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ok"),
        ) as sel,
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": False,
        }
        ensure_firewall_enabled()
    assert sel.call_args.args[0] == "ufw"
