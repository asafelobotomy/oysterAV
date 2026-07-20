"""Tests for VirusEvent bridge (ADR-008 Phase 3)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from oyst_core.virusevent import (
    ENV_FILENAME,
    ENV_VIRUSNAME,
    handle_virusevent,
    install_wrapper,
    virusevent_status,
)


def test_handle_requires_env_filename(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HOME", str(tmp_path))
    result = handle_virusevent(env={}, quarantine=False)
    assert result["ok"] is False


def test_handle_quarantines_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HOME", str(tmp_path))
    victim = tmp_path / "bad.bin"
    victim.write_bytes(b"eicar")
    env = {ENV_FILENAME: str(victim), ENV_VIRUSNAME: "Eicar-Test"}
    with (
        patch("oyst_core.virusevent.EventLog") as elog,
        patch("oyst_core.virusevent.SecurityAudit") as audit,
        patch("oyst_core.virusevent.QuarantineVault") as vault_cls,
        patch("oyst_core.virusevent._notify"),
        patch("oyst_core.virusevent.load_config") as load_cfg,
    ):
        load_cfg.return_value.quarantine.auto = True
        vault_cls.return_value.add = MagicMock()
        elog.return_value.log = MagicMock()
        audit.return_value.log = MagicMock()
        result = handle_virusevent(env=env, quarantine=True)
    assert result["ok"] is True
    assert result["quarantined"] is True
    vault_cls.return_value.add.assert_called_once()


def test_virusevent_status_detects_oysterav(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    wrapper = tmp_path / "bin" / "oyst-virusevent"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/bin/sh\n", encoding="utf-8")
    conf.write_text(f"VirusEvent {wrapper}\n", encoding="utf-8")
    with patch("oyst_core.virusevent.wrapper_path", return_value=wrapper):
        status = virusevent_status(conf_paths=[conf])
    assert status["configured"] is True
    assert status["owned_by_oysterav"] is True
    assert status["handoff"] is False


def test_virusevent_status_foreign_handoff(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("VirusEvent /usr/local/bin/notify-admin.sh\n", encoding="utf-8")
    status = virusevent_status(conf_paths=[conf])
    assert status["configured"] is True
    assert status["owned_by_oysterav"] is False
    assert status["handoff"] is True


def test_install_wrapper(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("HOME", str(tmp_path))
    with patch("oyst_core.virusevent.data_dir", return_value=tmp_path / "share"):
        result = install_wrapper()
    assert result["ok"] is True
    path = Path(str(result["path"]))
    assert path.is_file()
    assert "virusevent handle" in path.read_text(encoding="utf-8")
