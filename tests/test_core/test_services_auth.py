"""Tests for fine-grained polkit policy, services, and auth grants."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.privileged.auth_grant import (
    auth_status,
    build_service_lifecycle_rules,
    grant_service_lifecycle,
    revoke_service_lifecycle,
)
from oyst_core.privileged.install_privileged_helper import (
    POLICY_VERSION,
    POLKIT_ACTION_IDS,
    SERVICE_LIFECYCLE_ACTION_IDS,
    build_polkit_policy,
    install_privileged_helper,
)
from oyst_core.privileged.validators import ALLOWED_SYSTEMCTL_UNITS, validate_unit
from oyst_core.services import SERVICE_NAMES, set_service


def test_polkit_policy_has_argv1_scoped_actions() -> None:
    policy = build_polkit_policy()
    for action_id in POLKIT_ACTION_IDS:
        assert action_id in policy
    assert 'org.freedesktop.policykit.exec.argv1">systemctl<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">run<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">firewall<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">fail2ban<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">maldet-config<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">rkhunter-whitelist<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">install-script<' in policy
    assert "io.github.asafelobotomy.run-helper" not in policy
    assert POLICY_VERSION >= 3


def test_packaging_policy_matches_builder() -> None:
    packaged = Path("packaging/polkit/io.github.asafelobotomy.policy").read_text(encoding="utf-8")
    built = build_polkit_policy()
    for action_id in POLKIT_ACTION_IDS:
        assert action_id in packaged
        assert action_id in built
    for argv1 in (
        "systemctl",
        "run",
        "firewall",
        "fail2ban",
        "maldet-config",
        "rkhunter-whitelist",
        "install-script",
    ):
        assert f'exec.argv1">{argv1}</annotate>' in packaged
        assert f'exec.argv1">{argv1}</annotate>' in built


def test_install_privileged_helper_writes_policy(tmp_path: Path) -> None:
    with patch("oyst_core.privileged.install_privileged_helper.os.geteuid", return_value=0):
        result = install_privileged_helper(prefix=tmp_path)
    assert result["ok"] is True
    policy_path = tmp_path / "share" / "polkit-1" / "actions" / "io.github.asafelobotomy.policy"
    helper_path = tmp_path / "lib" / "oysterav" / "oyst-helper"
    assert policy_path.is_file()
    assert helper_path.is_file()
    text = policy_path.read_text(encoding="utf-8")
    assert "io.github.asafelobotomy.helper.systemctl" in text


def test_freshclam_timer_allowlisted() -> None:
    assert "clamav-freshclam.timer" in ALLOWED_SYSTEMCTL_UNITS
    assert "clamav-freshclam-once.timer" in ALLOWED_SYSTEMCTL_UNITS
    assert "clamav-clamonacc" in ALLOWED_SYSTEMCTL_UNITS
    assert validate_unit("clamav-freshclam.timer") == "clamav-freshclam.timer"
    assert validate_unit("clamav-freshclam-once.timer") == "clamav-freshclam-once.timer"
    assert validate_unit("clamav-clamonacc") == "clamav-clamonacc"


def test_build_service_lifecycle_rules_username() -> None:
    rules = build_service_lifecycle_rules("solon64")
    assert 'subject.user == "solon64"' in rules
    for action_id in SERVICE_LIFECYCLE_ACTION_IDS:
        assert action_id in rules
    assert "polkit.Result.YES" in rules


def test_grant_and_revoke_service_lifecycle(tmp_path: Path) -> None:
    with patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0):
        granted = grant_service_lifecycle("alice", prefix=tmp_path)
    assert granted["ok"] is True
    rules = tmp_path / "etc" / "polkit-1" / "rules.d" / "49-oysterav-service-lifecycle.rules"
    stamp = tmp_path / "usr" / "local" / "share" / "oysterav" / "service-lifecycle.grant"
    assert rules.is_file()
    assert stamp.is_file()
    status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is True
    assert status["granted_user"] == "alice"

    with patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0):
        revoked = revoke_service_lifecycle(prefix=tmp_path)
    assert revoked["ok"] is True
    assert not rules.is_file()
    assert not stamp.is_file()


def test_auth_status_uses_stamp_when_rules_unreadable(tmp_path: Path) -> None:
    stamp = tmp_path / "service-lifecycle.grant"
    stamp.write_text("user=bob\n", encoding="utf-8")
    rules = tmp_path / "missing" / "rules"
    status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is True
    assert status["granted_user"] == "bob"


def test_set_service_clamd_calls_systemctl_helper() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.services.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_unit", return_value="clamav-daemon"),
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_running", return_value=True),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("clamd", "on", boot=True)
    assert result["ok"] is True
    helper.assert_called_once_with("systemctl", ["enable-now", "clamav-daemon"])


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
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.services._freshclam_timer_unit", return_value="clamav-freshclam.timer"),
        patch("oyst_core.services.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("freshclam-timer", "on", boot=True)
    assert result["ok"] is True
    helper.assert_called_once_with("systemctl", ["enable-now", "clamav-freshclam.timer"])


def test_set_service_fail2ban() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.services.run_privileged_helper", return_value=mock_res),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("fail2ban", "off", boot=False)
    assert result["ok"] is True


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
