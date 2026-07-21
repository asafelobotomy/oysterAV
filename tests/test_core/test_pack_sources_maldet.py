"""Tests for maldet source/config helpers."""

from __future__ import annotations

from pathlib import Path

from oyst_core.pack_sources import configure_maldet_clamav, ensure_maldet_pub_paths


def test_configure_maldet_enables_clamav_and_user_access(tmp_path: Path) -> None:
    conf = tmp_path / "conf.maldet"
    conf.write_text(
        'scan_clamscan="0"\nscan_user_access="0"\n',
        encoding="utf-8",
    )
    assert configure_maldet_clamav(tmp_path) is True
    text = conf.read_text(encoding="utf-8")
    assert 'scan_clamscan="1"' in text
    assert 'scan_user_access="1"' in text
    assert "ignore_paths=" in text
    assert configure_maldet_clamav(tmp_path) is False


def test_ensure_maldet_pub_paths_creates_user_tree(tmp_path: Path) -> None:
    binary = tmp_path / "maldet"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    ok, msg = ensure_maldet_pub_paths(str(binary))
    assert ok is True
    user_dir = next((tmp_path / "pub").iterdir())
    assert (user_dir / "tmp").is_dir()
    assert (user_dir / "quar").is_dir()
    assert (user_dir / "sess").is_dir()
    assert (user_dir / "event_log").is_file()
    assert str(user_dir) in msg
