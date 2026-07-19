"""Tests for desktop autostart helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.config import OysterConfig, UiConfig, load_config, save_config, set_config_value
from oyst_core.desktop_util import (
    autostart_path,
    install_autostart,
    remove_autostart,
)


def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: home)
    cfg_dir = home / ".config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    save_config(OysterConfig(ui=UiConfig()))


def test_install_and_remove_autostart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(tmp_path, monkeypatch)
    result = install_autostart(minimized=True)
    assert result["ok"] is True
    path = Path(str(result["path"]))
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "--minimized" in text
    assert "Name=oysterAV" in text
    assert load_config().ui.run_at_startup is True

    removed = remove_autostart()
    assert removed["ok"] is True
    assert not path.is_file()
    assert load_config().ui.run_at_startup is False


def test_config_set_run_at_startup_writes_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    set_config_value("ui.run_at_startup", "true")
    assert autostart_path().is_file()
    set_config_value("ui.run_at_startup", "false")
    assert not autostart_path().is_file()


def test_config_set_start_minimized_rewrites_exec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    install_autostart(minimized=False)
    assert "--minimized" not in autostart_path().read_text(encoding="utf-8")
    set_config_value("ui.start_minimized", "true")
    assert "--minimized" in autostart_path().read_text(encoding="utf-8")


def test_desktop_status_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(tmp_path, monkeypatch)
    with patch("oyst_core.desktop_util.probe_tray_library", return_value={"available": False}):
        runner = CliRunner()
        result = runner.invoke(cli, ["desktop", "status", "--json"])
    assert result.exit_code == 0
    assert "run_at_startup" in result.output
    assert "tray" in result.output


def test_desktop_install_autostart_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(cli, ["desktop", "install-autostart", "--json"])
    assert result.exit_code == 0
    assert autostart_path().is_file()
