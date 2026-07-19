"""Tests for pack runtime resolver and manifest."""

from __future__ import annotations

from pathlib import Path

import pytest

from oyst_core.runtime.manifest import detect_arch, load_runtime_lock
from oyst_core.runtime.resolver import resolve_tool


def test_detect_arch() -> None:
    assert detect_arch() in ("x86_64", "aarch64", "i686", "armv7l")


def test_runtime_lock_created(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    lock = load_runtime_lock()
    assert lock.mode in ("full", "lite")
    assert (tmp_path / "runtime" / detect_arch() / "runtime.lock.json").is_file()


def test_resolve_tool_missing_in_lite_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    from oyst_core.config import OysterConfig, RuntimeConfig, load_config, save_config

    save_config(OysterConfig(runtime=RuntimeConfig(mode="lite")))
    load_config()
    resolved = resolve_tool("nonexistent-tool-xyz")
    assert resolved.path is None
    assert resolved.source == "missing"


def test_resolve_tool_does_not_confuse_lynis_with_other_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    from oyst_core.config import OysterConfig, RuntimeConfig, load_config, save_config

    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))
    load_config()
    arch = detect_arch()
    lynis_bin = tmp_path / "runtime" / arch / "lynis" / "lynis"
    lynis_bin.parent.mkdir(parents=True)
    lynis_bin.write_text("#!/bin/sh\necho lynis\n", encoding="utf-8")
    lynis_bin.chmod(0o755)
    assert resolve_tool("lynis").path == str(lynis_bin)
    assert resolve_tool("chkrootkit").path is None


def test_install_maldet_runtime_tree_stages_files_and_patches_inspath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    from oyst_core.config import OysterConfig, RuntimeConfig, save_config
    from oyst_core.runtime.bundles.scanners import install_maldet_runtime_tree

    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))

    source = tmp_path / "src" / "maldetect-1.6.6"
    files = source / "files"
    internals = files / "internals"
    internals.mkdir(parents=True)
    (internals / "internals.conf").write_text(
        "inspath=/usr/local/maldetect\ncnf=1\n", encoding="utf-8"
    )
    maldet_bin = files / "maldet"
    maldet_bin.write_text(
        "#!/bin/bash\ninspath='/usr/local/maldetect'\necho 1.6.6\n",
        encoding="utf-8",
    )
    maldet_bin.chmod(0o755)
    (files / "conf.maldet").write_text('scan_clamscan="0"\n', encoding="utf-8")

    dest = install_maldet_runtime_tree(source)
    assert (dest / "maldet").is_file()
    assert "/usr/local/maldetect" not in (dest / "maldet").read_text(encoding="utf-8")
    assert str(dest) in (dest / "maldet").read_text(encoding="utf-8")
    assert str(dest) in (dest / "internals" / "internals.conf").read_text(encoding="utf-8")
    assert resolve_tool("maldet").path == str(dest / "maldet")
    assert resolve_tool("freshclam").source != "runtime" or resolve_tool("freshclam").path.endswith(
        "freshclam"
    )


def test_resolve_tool_does_not_map_clamav_tools_to_maldet(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    from oyst_core.config import OysterConfig, RuntimeConfig, save_config

    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))
    arch = detect_arch()
    maldet_bin = tmp_path / "runtime" / arch / "maldetect" / "maldet"
    maldet_bin.parent.mkdir(parents=True)
    maldet_bin.write_text("#!/bin/sh\necho maldet\n", encoding="utf-8")
    maldet_bin.chmod(0o755)

    fresh = resolve_tool("freshclam")
    clam = resolve_tool("clamscan")
    assert fresh.path != str(maldet_bin)
    assert clam.path != str(maldet_bin)
