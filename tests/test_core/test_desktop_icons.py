"""Tests for user-local desktop icon / launcher install."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.desktop_icons import (
    ICON_NAME,
    ensure_desktop_integration,
    install_user_icons,
    install_user_launcher,
    remove_user_launcher,
    user_icons_root,
    user_launcher_path,
)


def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: home)
    return home


def test_install_user_icons_and_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(tmp_path, monkeypatch)
    icons = install_user_icons()
    assert icons["ok"] is True
    assert (user_icons_root() / "48x48" / "apps" / f"{ICON_NAME}.png").is_file()
    assert (user_icons_root() / "512x512" / "apps" / f"{ICON_NAME}.png").is_file()

    launcher = install_user_launcher()
    assert launcher["ok"] is True
    path = user_launcher_path()
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "Icon=oysterav" in text
    assert "StartupWMClass=io.github.asafelobotomy.OysterAV" in text
    assert "StartupNotify=true" in text
    assert "X-GNOME-Autostart" not in text

    again = ensure_desktop_integration()
    assert again["ok"] is True

    removed = remove_user_launcher()
    assert removed["removed"] is True
    assert not path.is_file()


def test_desktop_install_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_home(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(cli, ["desktop", "install", "--json"])
    assert result.exit_code == 0
    assert user_launcher_path().is_file()
    assert (user_icons_root() / "256x256" / "apps" / f"{ICON_NAME}.png").is_file()
