"""Fangfrisch pack helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from oyst_core.config import load_config, set_config_value
from oyst_core.packs.fangfrisch import FangfrischPack


def test_fangfrisch_ensure_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core import config as cfg_mod

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    monkeypatch.setattr(cfg_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(cfg_mod, "config_dir", lambda: cfg_dir)
    monkeypatch.setattr(cfg_mod, "config_path", lambda: cfg_dir / "config.toml")
    load_config()
    pack = FangfrischPack()
    ok, msg = pack.ensure_config(force=True)
    assert ok
    conf = pack._conf_path()
    assert conf.is_file()
    text = conf.read_text(encoding="utf-8")
    assert "local_directory" in text
    assert "sanesecurity" in text
    assert "urlhaus" in text
    assert "sqlite" in text
    assert str(tmp_path) in msg or "Wrote" in msg

    ok2, msg2 = pack.ensure_config(force=False)
    assert ok2
    assert "exists" in msg2

    set_config_value("fangfrisch.providers", "urlhaus")
    ok3, _msg3 = pack.ensure_config(force=True)
    assert ok3
    text3 = conf.read_text(encoding="utf-8")
    assert "[urlhaus]" in text3
    assert "[sanesecurity]" not in text3
