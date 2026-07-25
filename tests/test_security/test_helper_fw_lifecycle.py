"""Root firewall lifecycle (helper_fw_lifecycle) security properties."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oyst_core.privileged import helper_fw_lifecycle as life

pytestmark = pytest.mark.security


def test_install_firewall_package_as_root_runs_pm() -> None:
    with (
        patch.object(life, "detect_distro_family", return_value="arch"),
        patch.object(life, "resolve_trusted_argv", side_effect=lambda c: c),
        patch.object(life, "_run_cmd", return_value=(0, "ok")) as run,
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life.install_firewall_package_as_root("ufw")
    assert step["ok"] is True
    run.assert_called_once()
    cmd = run.call_args.args[0]
    assert cmd[0] == "pacman"
    assert "ufw" in cmd


def test_select_firewall_conflict_fail_closed() -> None:
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
            side_effect=[
                {
                    "conflict": True,
                    "ufw": True,
                    "firewalld": True,
                    "firewalld_active": True,
                    "ufw_active": True,
                    "active": "ufw",
                },
                {"conflict": True, "ufw": True, "firewalld": True, "active": "ufw"},
            ],
        ),
    ):
        step = life.select_firewall_as_root("ufw")
    assert step["ok"] is False
    assert "conflict" in step["message"].lower()
    assert any(cmd[:3] == ["systemctl", "stop", "firewalld"] for cmd in calls)
    assert not any("disable-now" in cmd for cmd in calls)


def test_select_soft_stop_systemctl_stop_not_disable_now() -> None:
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
            side_effect=[
                {
                    "ufw": True,
                    "firewalld": True,
                    "firewalld_active": True,
                    "ufw_active": False,
                    "conflict": False,
                    "active": "firewalld",
                },
                {"ufw": True, "firewalld": True, "conflict": False, "active": "none"},
            ],
        ),
        patch.object(
            life,
            "_ensure_ufw",
            return_value={"step": "firewall-ensure", "ok": True, "message": "ufw enabled"},
        ),
    ):
        step = life.select_firewall_as_root("ufw")
    assert step["ok"] is True
    assert any(c[:3] == ["systemctl", "stop", "firewalld"] for c in calls)
    assert not any("disable-now" in c for c in calls)


def test_ensure_ufw_auto_allows_ssh() -> None:
    status_calls = {"n": 0}

    def _status() -> str:
        status_calls["n"] += 1
        if status_calls["n"] == 1:
            return "Status: inactive"
        return "22/tcp ALLOW IN Anywhere"

    with (
        patch.object(life, "_ufw_status_text", side_effect=_status),
        patch.object(life, "_run_cmd", return_value=(0, "ok")) as run,
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_ufw(force_lockout=False)
    assert step["ok"] is True
    allow = run.call_args_list[0].args[0]
    assert allow[0] == "ufw"
    assert "allow" in allow
    assert "22" in " ".join(allow)


def test_ensure_firewalld_fail_closed_stops() -> None:
    calls: list[list[str]] = []

    def _run(cmd: list[str]) -> tuple[int, str]:
        calls.append(cmd)
        return 0, "ok"

    with (
        patch.object(life, "_run_cmd", side_effect=_run),
        patch.object(life, "_firewalld_ssh_ok", return_value=False),
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_firewalld(force_lockout=False)
    assert step["ok"] is False
    assert any(c[:3] == ["systemctl", "stop", "firewalld"] for c in calls)


def test_apply_lifecycle_install_before_select_and_short_circuit() -> None:
    order: list[str] = []

    def install(backend: str) -> dict:
        order.append(f"install:{backend}")
        return {"step": "firewall-install", "ok": False, "message": "fail", "soft_fail": True}

    def select(backend: str, *, force_lockout: bool = False) -> dict:
        order.append(f"select:{backend}")
        return {"step": "firewall-select", "ok": True}

    with (
        patch.object(life, "install_firewall_package_as_root", side_effect=install),
        patch.object(life, "select_firewall_as_root", side_effect=select),
    ):
        steps = life.apply_firewall_lifecycle_flags(
            ["--install-firewall=ufw", "--select-firewall=ufw"],
        )
    assert order == ["install:ufw"]
    assert len(steps) == 1
    assert steps[0]["ok"] is False


def test_apply_lifecycle_install_then_select_on_success() -> None:
    order: list[str] = []

    def install(backend: str) -> dict:
        order.append(f"install:{backend}")
        return {"step": "firewall-install", "ok": True, "message": "ok"}

    def select(backend: str, *, force_lockout: bool = False) -> dict:
        order.append(f"select:{backend}")
        return {"step": "firewall-select", "ok": True}

    with (
        patch.object(life, "install_firewall_package_as_root", side_effect=install),
        patch.object(life, "select_firewall_as_root", side_effect=select),
    ):
        steps = life.apply_firewall_lifecycle_flags(
            ["--install-firewall=firewalld", "--select-firewall=firewalld"],
        )
    assert order == ["install:firewalld", "select:firewalld"]
    assert len(steps) == 2
