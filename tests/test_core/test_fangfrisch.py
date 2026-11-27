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
    assert "urlhaus" not in text
    assert "sqlite" in text
    assert str(tmp_path) in msg or "Wrote" in msg

    ok2, msg2 = pack.ensure_config(force=False)
    assert ok2
    assert "exists" in msg2

    set_config_value("fangfrisch.providers", "interserver")
    ok3, _msg3 = pack.ensure_config(force=True)
    assert ok3
    text3 = conf.read_text(encoding="utf-8")
    assert "[interserver]" in text3
    assert "[sanesecurity]" not in text3


def test_retired_urlhaus_provider_is_dropped() -> None:
    """URLhaus exports need an abuse.ch Auth-Key since 2026-10-21 (410 Gone)."""
    from oyst_core.config_models import FangfrischConfig

    assert FangfrischConfig().providers == ["sanesecurity", "interserver"]
    assert FangfrischConfig(providers=["urlhaus"]).providers == ["sanesecurity", "interserver"]
    assert FangfrischConfig(providers=["urlhaus", "interserver"]).providers == ["interserver"]
    assert FangfrischConfig(providers=[]).providers == []
    with pytest.raises(ValueError):
        FangfrischConfig(providers=["nope"])


def test_stale_managed_conf_is_rewritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A conf oysterAV wrote with the retired URLhaus feed is refreshed without --force."""
    from oyst_core import config as cfg_mod
    from oyst_core.packs import fangfrisch as ff_mod

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    monkeypatch.setattr(cfg_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(ff_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(cfg_mod, "config_dir", lambda: cfg_dir)
    monkeypatch.setattr(cfg_mod, "config_path", lambda: cfg_dir / "config.toml")
    load_config()
    pack = FangfrischPack()
    conf = pack._conf_path()
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        ff_mod._MANAGED_HEADER + "\n[DEFAULT]\nenabled = no\n\n[urlhaus]\nenabled = yes\n",
        encoding="utf-8",
    )
    ok, msg = pack.ensure_config()
    assert ok
    assert "Wrote" in msg
    text = conf.read_text(encoding="utf-8")
    assert "[urlhaus]" not in text
    assert "[sanesecurity]" in text

    # A hand-written conf is left alone without --force.
    conf.write_text("[DEFAULT]\n[urlhaus]\nenabled = yes\n", encoding="utf-8")
    ok, msg = pack.ensure_config()
    assert ok
    assert "exists" in msg
    assert "[urlhaus]" in conf.read_text(encoding="utf-8")


def test_conf_uses_https_prefixes_and_lowercase_securiteinfo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fangfrisch's built-in Sanesecurity/InterServer prefixes are plain http."""
    from oyst_core.config_models import FangfrischConfig
    from oyst_core.packs.fangfrisch import FangfrischPack

    assert FangfrischConfig(providers=["securiteInfo"]).providers == ["securiteinfo"]
    text = FangfrischPack()._render_config(tmp_path, ["sanesecurity", "interserver"])
    assert "prefix = https://mirror.seichter.de/sanesecurity/" in text
    assert "prefix = https://sigs.interserver.net/" in text
    assert "http://" not in text


def test_refresh_with_logged_download_error_is_not_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fangfrisch exits 0 when a feed download fails; oysterAV must not call that a success."""
    from oyst_core.packs import fangfrisch as ff_mod
    from oyst_core.privileged.runner import CommandResult

    pack = FangfrischPack()
    conf = tmp_path / "fangfrisch.conf"
    conf.write_text("x", encoding="utf-8")
    monkeypatch.setattr(pack, "_binary", lambda: "/usr/bin/fangfrisch")
    monkeypatch.setattr(pack, "_conf_path", lambda: conf)
    monkeypatch.setattr(pack, "ensure_config", lambda force=False: (True, "ok"))
    out = "ERROR: HTTPSConnectionPool(host='sigs.interserver.net'): SSLError\nTraceback ..."
    monkeypatch.setattr(ff_mod, "run_command", lambda *a, **k: CommandResult(0, out, ""))
    ok, msg = pack.refresh()
    assert ok is False
    assert msg.startswith("ERROR: HTTPSConnectionPool")
    monkeypatch.setattr(ff_mod, "run_command", lambda *a, **k: CommandResult(0, "", ""))
    assert pack.refresh() == (True, "ok")
