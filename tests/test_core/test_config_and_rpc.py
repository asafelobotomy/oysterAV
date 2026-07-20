"""Tests for configuration and RPC client extensions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.config import (
    OysterConfig,
    SetupConfig,
    load_config,
    save_config,
    set_config_value,
    setup_status,
)
from oyst_core.models import ScanProfile
from oyst_core.packs.clamav import ClamAVPack


def test_setup_config_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")

    cfg = OysterConfig(setup=SetupConfig(completed=True, completed_at="2026-01-01T00:00:00+00:00"))
    save_config(cfg)
    loaded = load_config()
    assert loaded.setup.completed is True
    assert loaded.setup.completed_at == "2026-01-01T00:00:00+00:00"


def test_set_setup_completed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    set_config_value("setup.completed", "true")
    status = setup_status()
    assert status["completed"] is True
    assert status["completed_at"] is not None


def test_scan_tuning_config_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()

    with (
        patch("oyst_core.packs.clamav.ClamAVPack.ensure_ignore_sigs", return_value=None),
        patch(
            "oyst_core.packs.rkhunter_resolve.ensure_disable_tests_overlay",
            return_value={"ok": True},
        ),
        patch(
            "oyst_core.packs.fangfrisch.FangfrischPack.ensure_config",
            return_value=(True, "ok"),
        ),
    ):
        set_config_value("scan.max_filesize", "50M")
        set_config_value("scan.max_recursion", "12")
        set_config_value("scan.max_files", "20000")
        set_config_value("scan.exclude_dirs", "~/.cache,/tmp")
        set_config_value("scan.apply_limits_to", "all")
        set_config_value("clamav.ignore_sigs", "Sanesecurity.Spam.1,Win.Test.2")
        set_config_value("fangfrisch.providers", "urlhaus")
        set_config_value("clamonacc.prevention", "true")
        set_config_value("clamonacc.exclude_paths", "~/.cache")
        set_config_value("rkhunter.disable_tests", "suspscan,apps")
        set_config_value("lynis.quick", "false")
        set_config_value("scan.clamav_profile", "linux-only")

    cfg = load_config()
    assert cfg.scan.max_filesize == "50M"
    assert cfg.scan.max_recursion == 12
    assert cfg.scan.max_files == 20000
    assert cfg.scan.exclude_dirs == ["~/.cache", "/tmp"]
    assert cfg.scan.apply_limits_to == "all"
    assert cfg.clamav.ignore_sigs == ["Sanesecurity.Spam.1", "Win.Test.2"]
    assert cfg.fangfrisch.providers == ["urlhaus"]
    assert cfg.clamonacc.prevention is True
    assert cfg.clamonacc.exclude_paths == ["~/.cache"]
    assert cfg.rkhunter.disable_tests == ["suspscan", "apps"]
    assert cfg.lynis.quick is False
    assert cfg.scan.clamav_profile == "linux-only"
    assert cfg.schedule.backend == "inherit"

    # Deprecated alias still writes scan.clamav_profile
    with (
        patch("oyst_core.packs.clamav.ClamAVPack.ensure_ignore_sigs", return_value=None),
        patch(
            "oyst_core.packs.rkhunter_resolve.ensure_disable_tests_overlay",
            return_value={"ok": True},
        ),
        patch(
            "oyst_core.packs.fangfrisch.FangfrischPack.ensure_config",
            return_value=(True, "ok"),
        ),
        pytest.warns(DeprecationWarning, match="runtime.clamav_profile"),
    ):
        set_config_value("runtime.clamav_profile", "full")
    assert load_config().scan.clamav_profile == "full"

    with pytest.raises(KeyError):
        set_config_value("fangfrisch.providers", "not-a-provider")
    with pytest.raises(KeyError):
        set_config_value("scan.apply_limits_to", "sometimes")


def test_clamav_quick_scan_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    pack = ClamAVPack()
    argv: list[str] = ["clamscan", "-r", "--stdout", "/tmp"]
    pack._append_profile_flags(argv, ScanProfile.QUICK)
    assert "--max-filesize=25M" in argv
    assert "--max-recursion=8" in argv
    assert "--max-files=10000" in argv


def test_clamav_full_scan_no_quick_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    pack = ClamAVPack()
    argv: list[str] = ["clamscan", "-r", "--stdout", "/tmp"]
    pack._append_profile_flags(argv, ScanProfile.FULL)
    assert "--max-filesize=25M" not in argv


def test_clamav_apply_limits_to_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    set_config_value("scan.apply_limits_to", "all")
    set_config_value("scan.max_filesize", "10M")
    pack = ClamAVPack()
    argv: list[str] = ["clamscan"]
    pack._append_profile_flags(argv, ScanProfile.FULL)
    assert "--max-filesize=10M" in argv


def test_clamav_linux_only_and_excludes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    set_config_value("scan.clamav_profile", "linux-only")
    set_config_value("scan.exclude_dirs", str(tmp_path / "cache"))
    pack = ClamAVPack()
    argv: list[str] = ["clamscan"]
    pack._append_exclude_dirs(argv)
    pack._append_profile_scan_mode(argv)
    assert any(a.startswith("--exclude-dir=") for a in argv)
    assert "--scan-pe=no" in argv


def test_migrate_runtime_clamav_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    path = cfg_dir / "config.toml"
    path.write_text(
        '[runtime]\nmode = "full"\nclamav_profile = "linux-only"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: path)
    with pytest.warns(DeprecationWarning, match="clamav_profile"):
        cfg = load_config()
    assert cfg.scan.clamav_profile == "linux-only"
    assert "clamav_profile" not in cfg.runtime.model_dump()


def test_effective_schedule_backend_inherit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.config import effective_schedule_backend

    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    load_config()
    set_config_value("scan.backend", "clamd")
    set_config_value("schedule.backend", "inherit")
    assert effective_schedule_backend() == "clamd"
    set_config_value("schedule.backend", "clamscan")
    assert effective_schedule_backend() == "clamscan"


def test_clamav_ignore_sigs_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    data = tmp_path / "data"
    cfg_dir.mkdir(parents=True)
    data.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.config.data_dir", lambda: data)
    monkeypatch.setattr(
        "oyst_core.packs.clamav.clamav_db_dir",
        lambda: data / "clamav" / "db",
    )
    monkeypatch.setattr("oyst_core.packs.clamav.is_full_mode", lambda: True)
    load_config()
    with patch("oyst_core.packs.clamav.ClamAVPack.ensure_ignore_sigs") as noop:
        # Persist only via set_config_value side-effect path under test below.
        noop.return_value = None
        set_config_value("clamav.ignore_sigs", "Foo.Bar.1")
    pack = ClamAVPack()
    path = pack.ensure_ignore_sigs()
    assert path is not None
    assert path.read_text(encoding="utf-8") == "Foo.Bar.1\n"


def test_oyst_client_pack_install_local() -> None:
    from oyst_core.client import OystClient

    with patch("oyst_core.pack_install.install_pack") as install:
        from oyst_core.pack_install import InstallResult

        install.return_value = InstallResult(ok=True, mode="installed", message="done")
        client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
        result = client.pack_install("clamav")
    assert result["ok"] is True


def test_oyst_client_rkhunter_scan_local() -> None:
    from oyst_core.client import OystClient

    with patch("oyst_core.rpc_handlers.jobs.run_rkhunter_scan") as scan:
        scan.return_value = {"ok": True, "findings": [], "warnings_count": 0}
        client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
        result = client.rkhunter_scan()
    assert result["ok"] is True


def test_oyst_client_setup_status_local() -> None:
    from oyst_core.client import OystClient

    client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
    status = client.setup_status()
    assert "completed" in status


def test_ui_theme_default_and_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")

    cfg = load_config()
    assert cfg.ui.theme == "gruvbox-dark-hard"

    set_config_value("ui.theme", "gruvbox-light-soft")
    assert load_config().ui.theme == "gruvbox-light-soft"

    with pytest.raises(KeyError, match="ui.theme"):
        set_config_value("ui.theme", "not-a-theme")

    set_config_value("schedule.time", "9:05")
    assert load_config().schedule.time == "09:05"

    with pytest.raises(KeyError, match="schedule.time"):
        set_config_value("schedule.time", "25:00")

    set_config_value("schedule.packs", "clamav")
    assert load_config().schedule.packs == ["clamav"]
    with pytest.raises(KeyError, match="unknown schedule packs"):
        set_config_value("schedule.packs", "not-a-real-pack")

    set_config_value("ui.security_news_sources", "fedora,arch,bogus")
    assert load_config().ui.security_news_sources == ["arch", "fedora"]

    set_config_value("ui.security_news_sources", "")
    assert load_config().ui.security_news_sources == ["arch", "ubuntu", "debian"]
