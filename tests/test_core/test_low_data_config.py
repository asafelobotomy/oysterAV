"""Low-severity config I/O regressions: escaping, atomic save, corrupt recovery."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest

from oyst_core import config as cfg_mod
from oyst_core.config import OysterConfig, load_config, save_config
from oyst_core.config_io import _toml_str


@pytest.fixture
def cfg_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / "config.toml"
    monkeypatch.setattr(cfg_mod, "config_path", lambda: path)
    return path


def test_toml_str_escapes_every_control_char() -> None:
    value = "".join(chr(c) for c in range(0x20)) + "\x7f" + '"\\end'
    parsed = tomllib.loads(f"v = {_toml_str(value)}\n")
    assert parsed["v"] == value


def test_save_load_roundtrip_with_control_chars(cfg_path: Path) -> None:
    cfg = OysterConfig()
    cfg.scan.profile = "".join(chr(c) for c in range(0x20)) + "\x7f"
    cfg.scan.exclude_dirs = ["/a\x1b[31m", '/b"\\']
    save_config(cfg)
    loaded = load_config()
    assert loaded.scan.profile == cfg.scan.profile
    assert loaded.scan.exclude_dirs == cfg.scan.exclude_dirs


def test_save_is_atomic_and_preserves_mode(cfg_path: Path) -> None:
    save_config(OysterConfig())
    os.chmod(cfg_path, 0o640)
    inode = cfg_path.stat().st_ino
    save_config(OysterConfig())
    assert cfg_path.stat().st_mode & 0o777 == 0o640
    # Replaced via rename, not truncated in place.
    assert cfg_path.stat().st_ino != inode
    leftovers = [p for p in cfg_path.parent.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []


def test_new_config_file_is_private(cfg_path: Path) -> None:
    save_config(OysterConfig())
    assert cfg_path.stat().st_mode & 0o777 == 0o600


def test_corrupt_config_falls_back_to_defaults_with_backup(cfg_path: Path) -> None:
    cfg_path.write_text('[scan]\nprofile = "unterminated\n', encoding="utf-8")
    loaded = load_config()
    assert loaded == OysterConfig()
    backups = list(cfg_path.parent.glob("config.toml.corrupt-*"))
    assert len(backups) == 1
    assert "unterminated" in backups[0].read_text(encoding="utf-8")


def test_invalid_values_fall_back_to_defaults(cfg_path: Path) -> None:
    cfg_path.write_text('[scan]\nmax_files = "lots"\n', encoding="utf-8")
    assert load_config() == OysterConfig()
    assert list(cfg_path.parent.glob("config.toml.corrupt-*"))


def test_terminal_show_raw_roundtrip(cfg_path: Path) -> None:
    from oyst_core.config import get_config_value, set_config_value

    save_config(OysterConfig())
    set_config_value("ui.terminal_show_raw", "true")
    assert load_config().ui.terminal_show_raw is True
    assert get_config_value("ui.terminal_show_raw") == "true"
    assert "terminal_show_raw = true" in cfg_path.read_text(encoding="utf-8")
