"""Tests for turning services on and off, and their status."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.services import SERVICE_NAMES, set_service


def test_set_service_clamd_calls_enable_stack() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.packs.clamav.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_unit", return_value="clamav-daemon"),
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_running", return_value=True),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("clamd", "on", boot=True)
    assert result["ok"] is True
    helper.assert_called_once_with(
        "clamd-cocontrol",
        ["enable-stack", "--clamd-unit=clamav-daemon"],
    )


def test_set_service_clamd_off_uses_systemctl_route() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.packs.clamav.run_systemctl_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_unit", return_value="clamav-daemon"),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("clamd", "off", boot=False)
    assert result["ok"] is True
    helper.assert_called_once_with("stop", "clamav-daemon")


def test_systemctl_route_av_up_vs_fail2ban() -> None:
    from oyst_core.privileged.runner import CommandResult
    from oyst_core.privileged.systemctl_route import run_systemctl_helper

    with (
        patch(
            "oyst_core.privileged.systemctl_route.run_privileged_helper",
            return_value=CommandResult(0, "", ""),
        ) as helper,
        patch("oyst_core.privileged.systemctl_route.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        run_systemctl_helper("enable-now", "clamav-daemon")
        helper.assert_called_with("systemctl-up", ["enable-now", "clamav-daemon"])
        run_systemctl_helper("start", "fail2ban")
        helper.assert_called_with("systemctl", ["start", "fail2ban"])
        run_systemctl_helper("stop", "clamav-daemon")
        helper.assert_called_with("systemctl", ["stop", "clamav-daemon"])


def test_systemctl_up_builder_rejects_stop_and_fail2ban() -> None:
    from unittest.mock import patch

    from oyst_core.privileged.helper_services import _build_systemctl_up_argv

    with patch("oyst_core.privileged.helper_services.assert_lifecycle_grant_not_stale"):
        with pytest.raises(ValueError, match="systemctl-up"):
            _build_systemctl_up_argv(["stop", "clamav-daemon"])
        with pytest.raises(ValueError, match="systemctl-up"):
            _build_systemctl_up_argv(["enable-now", "fail2ban"])
        assert _build_systemctl_up_argv(["enable-now", "clamav-daemon"]) == [
            "systemctl",
            "enable",
            "--now",
            "clamav-daemon",
        ]


def test_set_service_unknown_name() -> None:
    result = set_service("nginx", "on")  # type: ignore[arg-type]
    assert result["ok"] is False
    assert "unknown service" in str(result["message"])


def test_service_names_cover_plan() -> None:
    expected = {
        "clamd",
        "clamonacc",
        "freshclam-timer",
        "fail2ban",
        "maldet-monitor",
        "schedule-linger",
    }
    assert set(SERVICE_NAMES) == expected


def test_services_status_shape() -> None:
    from oyst_core.models import PackStatus, PackTier
    from oyst_core.services import services_status

    clam_doc = PackStatus(
        name="clamonacc",
        tier=PackTier.OPTIONAL,
        installed=True,
        details={"running": False},
    )
    f2b_doc = PackStatus(
        name="fail2ban",
        tier=PackTier.OPTIONAL,
        installed=True,
        details={"running": True},
    )

    with (
        patch(
            "oyst_core.packs.clamav.ClamAVPack.clamd_status",
            return_value={"running": True, "enabled": True, "unit": "clamav-daemon"},
        ),
        patch("oyst_core.packs.clamonacc.ClamonaccPack.doctor", return_value=clam_doc),
        patch("oyst_core.services.load_clamonacc_enabled", return_value=False),
        patch("oyst_core.services._freshclam_timer_unit", return_value="clamav-freshclam.timer"),
        patch(
            "oyst_core.services._systemctl_probe",
            side_effect=lambda unit: {
                "unit": unit,
                "active": unit == "fail2ban",
                "enabled": False,
            },
        ),
        patch("oyst_core.packs.fail2ban.Fail2banPack.doctor", return_value=f2b_doc),
        patch(
            "oyst_core.packs.maldet.MaldetPack.monitor_status",
            return_value={"running": False, "enabled": False},
        ),
        patch(
            "oyst_core.schedule_util.get_linger_status",
            return_value={"linger": True, "user": "alice"},
        ),
    ):
        status = services_status()

    assert set(status["names"]) == set(SERVICE_NAMES)
    services = status["services"]
    assert isinstance(services, dict)
    assert services["clamd"]["running"] is True
    assert services["fail2ban"]["running"] is True
    assert services["schedule-linger"]["running"] is True


def test_set_service_clamonacc_enable() -> None:
    with (
        patch("oyst_core.packs.clamonacc.ClamonaccPack.enable", return_value=(True, "enabled")),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("clamonacc", "on")
    assert result["ok"] is True


def test_set_service_freshclam_timer() -> None:
    """Lite mode toggles the distro unit (full mode uses the oysterAV user timer)."""
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.runtime.manifest.is_full_mode", return_value=False),
        patch("oyst_core.services._freshclam_timer_unit", return_value="clamav-freshclam.timer"),
        patch("oyst_core.services.run_systemctl_helper", return_value=mock_res) as helper,
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("freshclam-timer", "on", boot=True)
    assert result["ok"] is True
    helper.assert_called_once_with("enable-now", "clamav-freshclam.timer")


def test_set_service_fail2ban() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.services.run_systemctl_helper", return_value=mock_res) as helper,
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("fail2ban", "off", boot=False)
    assert result["ok"] is True
    helper.assert_called_once_with("stop", "fail2ban")


def test_set_service_maldet_monitor() -> None:
    with (
        patch("oyst_core.packs.maldet.MaldetPack.monitor_start", return_value=(True, "started")),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("maldet-monitor", "on")
    assert result["ok"] is True


def test_set_service_linger_on_and_off() -> None:
    with (
        patch(
            "oyst_core.schedule_util.enable_linger",
            return_value={"ok": True, "message": "linger enabled"},
        ),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        on = set_service("schedule-linger", "on")
    assert on["ok"] is True

    with (
        patch(
            "oyst_core.schedule_util.disable_linger",
            return_value={"ok": True, "message": "ok", "linger": False},
        ),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        off = set_service("schedule-linger", "off")
    assert off["ok"] is True


def test_freshclam_timer_unit_prefers_once_timer(monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core import services as services_mod

    def fake_exists(unit: str) -> bool:
        return unit == "clamav-freshclam-once.timer"

    monkeypatch.setattr(services_mod, "_unit_file_exists", fake_exists)
    assert services_mod._freshclam_timer_unit() == "clamav-freshclam-once.timer"
