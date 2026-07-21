"""Unit tests for high-risk pack modules (mocked subprocess/helper)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.config import OysterConfig, save_config
from oyst_core.models import FindingSeverity
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.packs.fail2ban import Fail2banPack
from oyst_core.packs.lynis import LynisPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.privileged.runner import CommandResult


def test_maldet_parse_findings() -> None:
    pack = MaldetPack()
    findings = pack.parse_findings(
        "SCAN COMPLETE\n"
        "maldet(1): {hit} malware hit Evil.Sig found for /tmp/bad.exe\n"
        "other line\n"
        "FOUND something /opt/x"
    )
    assert len(findings) == 1
    assert findings[0].path == "/tmp/bad.exe"
    assert findings[0].threat_name == "Evil.Sig"
    assert findings[0].severity == FindingSeverity.HIGH


def test_maldet_scan_argv() -> None:
    pack = MaldetPack()
    with (
        patch.object(pack, "_binary", return_value="/usr/bin/maldet"),
        patch(
            "oyst_core.packs.maldet.run_command",
            return_value=CommandResult(0, "ok", ""),
        ) as run,
    ):
        ok, _ = pack.scan("/tmp/scanme")
    assert ok is True
    run.assert_called_once()
    assert run.call_args[0][0] == ["/usr/bin/maldet", "-a", "/tmp/scanme"]


def test_maldet_scan_not_installed() -> None:
    pack = MaldetPack()
    with patch.object(pack, "_binary", return_value=None):
        ok, msg = pack.scan("/tmp")
    assert ok is False
    assert "not installed" in msg


def test_clamav_parse_findings() -> None:
    pack = ClamAVPack()
    result = CommandResult(
        1,
        "/tmp/eicar.com: Eicar-Test-Signature FOUND\n----------- SCAN SUMMARY -----------\n",
        "",
    )
    findings = pack.parse_findings(result)
    assert len(findings) == 1
    assert findings[0].path == "/tmp/eicar.com"
    assert "Eicar" in findings[0].threat_name


def test_clamav_clamd_ensure_already_running() -> None:
    pack = ClamAVPack()
    with patch.object(pack, "clamd_status", return_value={"running": True}):
        ok, msg = pack.clamd_ensure()
    assert ok is True
    assert "already running" in msg


def test_clamav_clamd_ensure_starts() -> None:
    pack = ClamAVPack()
    with (
        patch.object(pack, "clamd_status", return_value={"running": False}),
        patch.object(pack, "_clamd_action", return_value=(True, "started")) as action,
    ):
        ok, msg = pack.clamd_ensure()
    assert ok is True
    action.assert_called_once_with("start")
    assert msg == "started"


def test_fail2ban_service_status_parses_jails() -> None:
    pack = Fail2banPack()
    stdout = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, apache-auth\n"
    with (
        patch("oyst_core.packs.fail2ban.which", return_value="/usr/bin/fail2ban-client"),
        patch(
            "oyst_core.packs.fail2ban.run_command",
            return_value=CommandResult(0, stdout, ""),
        ),
    ):
        status = pack.service_status()
    assert status["installed"] is True
    assert status["running"] is True
    assert status["jails"] == ["sshd", "apache-auth"]


def test_fail2ban_unban_with_jail() -> None:
    pack = Fail2banPack()
    mock_res = MagicMock(returncode=0, stdout="OK", stderr="")
    with (
        patch("oyst_core.packs.fail2ban.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.fail2ban.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        ok, msg = pack.unban("1.2.3.4", jail="sshd")
    assert ok is True
    helper.assert_called_once_with(
        "fail2ban",
        ["unban-flow", "1.2.3.4", "--jail", "sshd"],
    )
    assert msg == "OK"


def test_fail2ban_unban_global() -> None:
    pack = Fail2banPack()
    mock_res = MagicMock(returncode=0, stdout="", stderr="")
    with (
        patch("oyst_core.packs.fail2ban.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.fail2ban.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        ok, _ = pack.unban("8.8.8.8")
    assert ok is True
    helper.assert_called_once_with("fail2ban", ["unban-flow", "8.8.8.8"])


def test_fail2ban_unban_ignore_persist_one_helper_call() -> None:
    pack = Fail2banPack()
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch("oyst_core.packs.fail2ban.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.fail2ban.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        ok, _ = pack.unban("1.2.3.4", jail="sshd", ignore=True, persist=True)
    assert ok is True
    helper.assert_called_once_with(
        "fail2ban",
        ["unban-flow", "1.2.3.4", "--jail", "sshd", "--ignore", "--persist"],
    )


def test_maldet_monitor_start_one_helper_call() -> None:
    pack = MaldetPack()
    mock_res = MagicMock(returncode=0, stdout="ok", stderr="")
    with (
        patch.object(pack, "_binary", return_value="/usr/bin/maldet"),
        patch("oyst_core.packs.maldet.which", return_value="/usr/bin/inotifywait"),
        patch.object(pack, "_inotify_watches", return_value=65536),
        patch.object(pack, "_clamonacc_overlaps", return_value=[]),
        patch.object(pack, "_monitor_mode_value", return_value="users"),
        patch("oyst_core.packs.maldet.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.packs.maldet.load_config") as load_cfg,
        patch("oyst_core.packs.maldet.save_config"),
        patch("oyst_core.packs.maldet.SecurityAudit") as audit_cls,
    ):
        cfg = MagicMock()
        cfg.maldet_monitor.enabled = False
        load_cfg.return_value = cfg
        audit_cls.return_value.log = MagicMock()
        ok, msg = pack.monitor_start()
    assert ok is True
    assert msg == "ok"
    helper.assert_called_once_with("maldet-config", ["start-monitor", "users"])


def test_clamonacc_add_remove_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    save_config(OysterConfig())

    pack = ClamonaccPack()
    pack.add_path(str(tmp_path / "Downloads"))
    cfg = __import__("oyst_core.config", fromlist=["load_config"]).load_config()
    assert str(tmp_path / "Downloads") in cfg.clamonacc.paths

    assert pack.remove_path(str(tmp_path / "Downloads")) is True
    cfg2 = __import__("oyst_core.config", fromlist=["load_config"]).load_config()
    assert str(tmp_path / "Downloads") not in cfg2.clamonacc.paths
    assert pack.remove_path(str(tmp_path / "Downloads")) is False


def test_clamonacc_enable_calls_clamd_and_start() -> None:
    pack = ClamonaccPack()
    with (
        patch("oyst_core.packs.clamonacc.set_config_value") as set_cfg,
        patch("oyst_core.packs.clamonacc.ClamAVPack.clamd_ensure", return_value=(True, "ok")),
        patch.object(pack, "start", return_value=(True, "started")) as start,
    ):
        ok, msg = pack.enable()
    assert ok is True
    set_cfg.assert_called_with("clamonacc.enabled", "true")
    start.assert_called_once()
    assert msg == "started"


def test_lynis_parse_hardening_index() -> None:
    pack = LynisPack()
    assert pack._parse_hardening_index("Hardening index : 72\n") == 72
    assert pack._parse_hardening_index("no score") is None


def test_lynis_resolve_profile_missing() -> None:
    pack = LynisPack()
    with pytest.raises(FileNotFoundError, match="profile not found"):
        pack.resolve_profile("does-not-exist-xyz", "host")


def test_lynis_audit_argv() -> None:
    pack = LynisPack()
    with (
        patch(
            "oyst_core.packs.lynis.resolve_pack_binary",
            return_value=("/usr/bin/lynis", "system"),
        ),
        patch.object(pack, "resolve_profile", return_value=None),
        patch.object(pack, "_cache_report"),
        patch(
            "oyst_core.packs.lynis.run_privileged",
            return_value=CommandResult(0, "Hardening index : 65\n", ""),
        ) as run,
        patch("oyst_core.packs.lynis.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        ok, _out, score = pack.audit(quick=True)
    assert ok is True
    assert score == 65
    argv = run.call_args[0][0]
    assert argv[:4] == ["/usr/bin/lynis", "audit", "system", "--no-colors"]
    assert "--quick" in argv
