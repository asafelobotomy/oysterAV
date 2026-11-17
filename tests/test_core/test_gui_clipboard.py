"""The GTK app's clipboard helper: wl-copy first, so the text outlives the dialog."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from oysterav.gui import clipboard


def _fake_wl_copy(bin_dir: Path, out: Path, code: int = 0) -> None:
    exe = bin_dir / "wl-copy"
    exe.write_text(f"#!/bin/sh\ncat > {out}\nexit {code}\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)


def test_wl_copy_receives_the_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "got.txt"
    _fake_wl_copy(tmp_path, out)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}/usr/bin:/bin")
    assert clipboard.copy_to_clipboard("oyst-cli setup run\nline two") is True
    assert out.read_text() == "oyst-cli setup run\nline two"


def test_falls_back_to_gdk_when_wl_copy_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    seen: list[str] = []
    monkeypatch.setattr(clipboard, "_gdk_copy", lambda t: seen.append(t) or True)
    assert clipboard.copy_to_clipboard("x") is True
    assert seen == ["x"]


def test_failing_wl_copy_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_wl_copy(tmp_path, tmp_path / "got.txt", code=1)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}/usr/bin:/bin")
    monkeypatch.setattr(clipboard, "_gdk_copy", lambda _t: False)
    assert clipboard.copy_to_clipboard("x") is False
