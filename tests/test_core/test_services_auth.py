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
    assert 'org.freedesktop.policykit.exec.argv1">systemctl-up<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">run<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">firewall<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">fail2ban<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">maldet-config<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">rkhunter-whitelist<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">clamd-cocontrol<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">setup-harden<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">setup-concert<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">scan-concert<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">install-script<' in policy
    assert 'org.freedesktop.policykit.exec.argv1">run-sealed<' in policy
    assert "io.github.asafelobotomy.run-helper" not in policy
    assert POLICY_VERSION >= 11
    assert 'allow_active">auth_admin<' in policy or "auth_admin" in policy
    # run action must not use auth_admin_keep
    run_idx = policy.find("helper.run")
    assert run_idx != -1
    run_slice = policy[run_idx : run_idx + 500]
    assert "auth_admin_keep" not in run_slice
    # full systemctl (stop/disable) must not use auth_admin_keep
    sys_marker = 'id="io.github.asafelobotomy.helper.systemctl"'
    sys_idx = policy.find(sys_marker)
    assert sys_idx != -1
    sys_slice = policy[sys_idx : sys_idx + 500]
    assert "auth_admin_keep" not in sys_slice
    up_idx = policy.find('id="io.github.asafelobotomy.helper.systemctl-up"')
    assert up_idx != -1
    up_slice = policy[up_idx : up_idx + 500]
    assert "auth_admin_keep" in up_slice
    assert "/usr/lib/oysterav/oyst-helper" in policy
    assert "io.github.asafelobotomy.helper.systemctl-up" in SERVICE_LIFECYCLE_ACTION_IDS
    assert "io.github.asafelobotomy.helper.systemctl" not in SERVICE_LIFECYCLE_ACTION_IDS


def test_packaging_policy_matches_builder() -> None:
    packaged = Path("packaging/polkit/io.github.asafelobotomy.policy").read_text(encoding="utf-8")
    built = build_polkit_policy()
    for action_id in POLKIT_ACTION_IDS:
        assert action_id in packaged
        assert action_id in built
    for argv1 in (
        "systemctl",
        "systemctl-up",
        "run",
        "firewall",
        "fail2ban",
        "maldet-config",
        "rkhunter-whitelist",
        "clamd-cocontrol",
        "setup-harden",
        "setup-concert",
        "scan-concert",
        "install-script",
        "run-sealed",
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


def test_helper_script_embeds_site_root_when_system_python_lacks_oyst_core() -> None:
    from oyst_core.privileged import install_privileged_helper as mod

    with (
        patch.object(mod, "_resolve_trusted_helper_python", return_value="/usr/bin/python3"),
        patch.object(mod, "_python_imports_oyst_core", side_effect=[False, True]),
        patch.object(
            mod,
            "_oyst_core_site_root",
            return_value=Path("/usr/lib/oysterav-site").resolve(),
        ),
        patch.object(
            mod,
            "_validate_site_root",
            side_effect=lambda p, **_kw: Path("/usr/lib/oysterav-site"),
        ),
    ):
        text = mod._helper_script_text(allow_untrusted_python=False)
    assert "sys.path.insert" in text
    assert "/usr/lib/oysterav-site" in text
    assert "from oyst_core.privileged.oyst_helper import main" in text


def test_helper_script_rejects_user_writable_site_root(tmp_path: Path) -> None:
    from oyst_core.privileged import install_privileged_helper as mod

    site = tmp_path / "site"
    (site / "oyst_core").mkdir(parents=True)
    (site / "oyst_core" / "__init__.py").write_text("", encoding="utf-8")

    with (
        patch.object(mod, "_resolve_trusted_helper_python", return_value="/usr/bin/python3"),
        patch.object(mod, "_python_imports_oyst_core", return_value=False),
        patch.object(mod, "_oyst_core_site_root", return_value=site),
    ):
        try:
            mod._helper_script_text(allow_untrusted_python=False)
            raise AssertionError("expected OSError for user-writable site root")
        except OSError as exc:
            assert "root-owned" in str(exc) or "user-writable" in str(exc)


def test_helper_script_allows_user_site_root_in_dev_mode(tmp_path: Path) -> None:
    from oyst_core.privileged import install_privileged_helper as mod

    site = tmp_path / "site"
    (site / "oyst_core").mkdir(parents=True)
    (site / "oyst_core" / "__init__.py").write_text("", encoding="utf-8")

    with (
        patch.object(mod, "_resolve_trusted_helper_python", return_value="/usr/bin/python3"),
        patch.object(mod, "_python_imports_oyst_core", side_effect=[False, True]),
        patch.object(mod, "_oyst_core_site_root", return_value=site),
    ):
        text = mod._helper_script_text(allow_untrusted_python=True)
    assert str(site) in text
    assert "sys.path.insert" in text


def test_helper_script_plain_when_system_python_has_oyst_core() -> None:
    from oyst_core.privileged import install_privileged_helper as mod

    with (
        patch.object(mod, "_resolve_trusted_helper_python", return_value="/usr/bin/python3"),
        patch.object(mod, "_python_imports_oyst_core", return_value=True),
    ):
        text = mod._helper_script_text(allow_untrusted_python=False)
    assert "sys.path.insert" not in text
    assert text.startswith("#!/usr/bin/python3\n")


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
    assert "subject.active == true" in rules
    assert "subject.local == true" in rules
    for action_id in SERVICE_LIFECYCLE_ACTION_IDS:
        assert action_id in rules
    assert 'action.id == "io.github.asafelobotomy.helper.systemctl-up"' in rules
    assert 'action.id == "io.github.asafelobotomy.helper.systemctl"' not in rules
    assert "polkit.Result.YES" in rules


def test_grant_and_revoke_service_lifecycle(tmp_path: Path) -> None:
    with patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0):
        granted = grant_service_lifecycle("alice", prefix=tmp_path)
    assert granted["ok"] is True
    assert "expires" in granted
    rules = tmp_path / "etc" / "polkit-1" / "rules.d" / "49-oysterav-service-lifecycle.rules"
    stamp = tmp_path / "usr" / "local" / "share" / "oysterav" / "service-lifecycle.grant"
    assert rules.is_file()
    assert stamp.is_file()
    stamp_text = stamp.read_text(encoding="utf-8")
    assert "expires=" in stamp_text
    assert "version=10" in stamp_text
    assert (tmp_path / "etc" / "systemd" / "system" / "oysterav-auth-grant-expire.timer").is_file()
    assert (tmp_path / "usr" / "lib" / "oysterav" / "oyst-auth-expire").is_file()
    status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is True
    assert status["expired"] is False
    assert status["granted_user"] == "alice"

    with patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0):
        revoked = revoke_service_lifecycle(prefix=tmp_path)
    assert revoked["ok"] is True
    assert not rules.is_file()
    assert not stamp.is_file()
    timer = tmp_path / "etc" / "systemd" / "system" / "oysterav-auth-grant-expire.timer"
    assert not timer.is_file()


def test_auth_status_uses_stamp_when_rules_unreadable(tmp_path: Path) -> None:
    from datetime import UTC, datetime, timedelta

    stamp = tmp_path / "service-lifecycle.grant"
    future = (datetime.now(UTC) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    stamp.write_text(f"user=bob\nexpires={future}\nversion=10\n", encoding="utf-8")
    rules = tmp_path / "missing" / "rules"
    status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is True
    assert status["granted_user"] == "bob"
    assert status["expired"] is False


def test_auth_status_expired_legacy_stamp(tmp_path: Path) -> None:
    stamp = tmp_path / "service-lifecycle.grant"
    stamp.write_text("user=bob\n", encoding="utf-8")
    rules = tmp_path / "missing" / "rules"
    status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is False
    assert status["expired"] is True


def test_auth_status_survives_is_file_permission_error(tmp_path: Path) -> None:
    """CI images may make polkit rules.d unstatable (PermissionError on is_file)."""
    stamp = tmp_path / "service-lifecycle.grant"
    rules = tmp_path / "49-oysterav-service-lifecycle.rules"
    with patch.object(Path, "is_file", side_effect=PermissionError(13, "Permission denied")):
        status = auth_status(rules_path=rules, stamp_path=stamp)
    assert status["granted"] is False
    assert "error" in status


def test_set_service_clamd_calls_systemctl_up_helper() -> None:
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.services.run_systemctl_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_unit", return_value="clamav-daemon"),
        patch("oyst_core.packs.clamav.ClamAVPack.clamd_running", return_value=True),
        patch("oyst_core.services.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = set_service("clamd", "on", boot=True)
    assert result["ok"] is True
    helper.assert_called_once_with("enable-now", "clamav-daemon")


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
    from oyst_core.privileged.helper_services import _build_systemctl_up_argv

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
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
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
