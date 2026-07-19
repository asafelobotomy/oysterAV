"""Light unit coverage for thinner packs and scanner runtime helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.packs.chkrootkit import ChkrootkitPack
from oyst_core.packs.unhide import UnhidePack
from oyst_core.privileged.runner import CommandResult
from oyst_core.runtime.bundles.scanners import install_maldet_runtime_tree


def test_chkrootkit_parse_findings() -> None:
    pack = ChkrootkitPack()
    findings = pack.parse_findings("Checking `foo'... INFECTED\nclean\nSUSPECT something")
    assert len(findings) == 2
    assert all(f.threat_name == "chkrootkit-hit" for f in findings)


def test_chkrootkit_scan_not_installed() -> None:
    pack = ChkrootkitPack()
    with patch(
        "oyst_core.packs.chkrootkit.resolve_pack_binary",
        return_value=(None, "missing"),
    ):
        ok, msg = pack.scan()
    assert ok is False
    assert "not installed" in msg


def test_unhide_parse_findings() -> None:
    pack = UnhidePack()
    findings = pack.parse_findings("Found HIDDEN PID: 1234\nnothing")
    assert len(findings) == 1
    assert findings[0].threat_name == "hidden-process"


def test_unhide_scan_argv() -> None:
    pack = UnhidePack()
    with (
        patch.object(pack, "_binary", return_value="/usr/bin/unhide"),
        patch(
            "oyst_core.packs.unhide.run_privileged",
            return_value=CommandResult(0, "ok", ""),
        ) as run,
    ):
        ok, _ = pack.scan(mode="quick")
    assert ok is True
    run.assert_called_once_with(["/usr/bin/unhide", "quick"], timeout=600)


def test_install_maldet_runtime_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "src"
    files = source / "files"
    files.mkdir(parents=True)
    (files / "maldet").write_text("#!/bin/sh\ninspath=/usr/local/maldetect\n", encoding="utf-8")
    (files / "conf.maldet").write_text("inspath=/usr/local/maldetect\n", encoding="utf-8")
    dest_root = tmp_path / "runtime" / "maldet"
    bin_dir = tmp_path / "runtime" / "bin"
    bin_dir.mkdir(parents=True)
    monkeypatch.setattr(
        "oyst_core.runtime.bundles.scanners.runtime_maldet_prefix",
        lambda: dest_root,
    )
    monkeypatch.setattr(
        "oyst_core.runtime.bundles.scanners.runtime_bin_dir",
        lambda: bin_dir,
    )
    dest = install_maldet_runtime_tree(source)
    assert dest == dest_root
    assert (dest / "maldet").is_file()
    assert (bin_dir / "maldet").is_symlink()


def test_install_maldet_runtime_tree_requires_files(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        install_maldet_runtime_tree(tmp_path / "empty")
