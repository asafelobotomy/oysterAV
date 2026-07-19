"""Tests for pack_jobs wrappers and runtime full bootstrap."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.models import PackStatus, PackTier
from oyst_core.pack_jobs import run_rkhunter_propupd, run_rkhunter_scan, run_rkhunter_update
from oyst_core.runtime_full_bootstrap import run_full_runtime_bootstrap


def test_rkhunter_scan_job_busy() -> None:
    events = MagicMock()
    events.acquire_job_lock.return_value = False
    with patch("oyst_core.pack_jobs.EventLog", return_value=events):
        result = run_rkhunter_scan()
    assert result["ok"] is False
    assert result["error"] == "job already running"
    assert result["findings"] == []


def test_rkhunter_scan_success() -> None:
    events = MagicMock()
    events.acquire_job_lock.return_value = True
    pack = MagicMock()
    pack.doctor.return_value = PackStatus(
        name="rkhunter", tier=PackTier.RECOMMENDED, installed=True
    )
    pack.scan.return_value = (True, "Warning: foo\n")
    finding = MagicMock()
    finding.model_dump.return_value = {"path": "foo", "threat_name": "warn"}
    pack.parse_findings.return_value = [finding]

    with (
        patch("oyst_core.pack_jobs.EventLog", return_value=events),
        patch("oyst_core.pack_jobs.RKHunterPack", return_value=pack),
        patch("oyst_core.pack_jobs.load_config") as cfg,
    ):
        cfg.return_value.rkhunter.skip_keypress = True
        result = run_rkhunter_scan()

    assert result["ok"] is True
    assert result["warnings_count"] == 1
    events.release_job_lock.assert_called_once()


def test_rkhunter_update_not_installed() -> None:
    pack = MagicMock()
    pack.doctor.return_value = PackStatus(
        name="rkhunter",
        tier=PackTier.RECOMMENDED,
        installed=False,
        install_hint="install rkhunter",
    )
    with patch("oyst_core.pack_jobs.RKHunterPack", return_value=pack):
        result = run_rkhunter_update()
    assert result["ok"] is False
    assert "not installed" in str(result["message"])


def test_rkhunter_propupd_ok() -> None:
    pack = MagicMock()
    pack.doctor.return_value = PackStatus(
        name="rkhunter", tier=PackTier.RECOMMENDED, installed=True
    )
    pack.propupd.return_value = (True, "updated")
    with patch("oyst_core.pack_jobs.RKHunterPack", return_value=pack):
        result = run_rkhunter_propupd()
    assert result == {"ok": True, "message": "updated"}


def test_full_bootstrap_requires_full_mode() -> None:
    with patch("oyst_core.runtime_full_bootstrap.is_full_mode", return_value=False):
        result = run_full_runtime_bootstrap()
    assert result["ok"] is False
    assert "full mode" in result["message"]
    assert result["steps"] == []


def test_full_bootstrap_happy_path() -> None:
    with (
        patch("oyst_core.runtime_full_bootstrap.is_full_mode", return_value=True),
        patch(
            "oyst_core.runtime_full_bootstrap.bootstrap_runtime",
            return_value=[{"pack": "lynis", "ok": True, "message": "ok"}],
        ),
        patch(
            "oyst_core.runtime_full_bootstrap.update_runtime",
            return_value={"ok": True, "clamav": {"message": "sigs ok"}},
        ),
        patch(
            "oyst_core.runtime_full_bootstrap.run_bootstrap",
            return_value=[{"step": "freshclam", "ok": True}],
        ),
        patch("oyst_core.runtime_full_bootstrap.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = run_full_runtime_bootstrap(skip_lynis=True)

    assert result["ok"] is True
    steps = {s["step"] for s in result["steps"]}
    assert "install-lynis" in steps
    assert "signatures" in steps
    assert "maintenance" in steps


def test_full_bootstrap_skip_install_and_sigs() -> None:
    with (
        patch("oyst_core.runtime_full_bootstrap.is_full_mode", return_value=True),
        patch("oyst_core.runtime_full_bootstrap.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = run_full_runtime_bootstrap(
            skip_install=True,
            update_signatures=False,
            run_maintenance=False,
        )
    assert any(s.get("skipped") and s["step"] == "install" for s in result["steps"])
    assert any(s.get("skipped") and s["step"] == "signatures" for s in result["steps"])


def test_freshclam_update_via_runtime_conf() -> None:
    from oyst_core.packs.freshclam import FreshclamPack
    from oyst_core.privileged.runner import CommandResult

    pack = FreshclamPack()
    with (
        patch(
            "oyst_core.packs.freshclam.resolve_pack_binary",
            return_value=("/usr/bin/freshclam", "system"),
        ),
        patch(
            "oyst_core.packs.freshclam.freshclam_conf_path",
            return_value=MagicMock(is_file=lambda: True),
        ),
        patch(
            "oyst_core.packs.freshclam.update_clamav_signatures",
            return_value={"ok": True, "message": "sigs"},
        ),
    ):
        ok, msg = pack.update()
    assert ok is True
    assert msg == "sigs"

    with (
        patch(
            "oyst_core.packs.freshclam.resolve_pack_binary",
            return_value=("/usr/bin/freshclam", "system"),
        ),
        patch(
            "oyst_core.packs.freshclam.freshclam_conf_path",
            return_value=MagicMock(is_file=lambda: False),
        ),
        patch(
            "oyst_core.packs.freshclam.run_command",
            return_value=CommandResult(0, "ClamAV update process started\n", ""),
        ),
    ):
        ok2, msg2 = pack.update()
    assert ok2 is True
    assert "ClamAV" in msg2


def test_freshclam_update_not_installed() -> None:
    from oyst_core.packs.freshclam import FreshclamPack

    with patch(
        "oyst_core.packs.freshclam.resolve_pack_binary",
        return_value=(None, "missing"),
    ):
        ok, msg = FreshclamPack().update()
    assert ok is False
    assert "not installed" in msg
