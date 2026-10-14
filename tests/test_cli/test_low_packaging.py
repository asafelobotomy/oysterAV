"""Low-severity packaging audit fixes: version sync, metainfo, Flathub pins, helpers."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
PKG = ROOT / "packaging"


def _sync_version() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sync_version", ROOT / "scripts" / "sync_version.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sv = _sync_version()


def test_metainfo_date_kept_when_version_unchanged() -> None:
    text = '<release version="0.2.2" date="2026-07-27"/>'
    assert sv._replace_metainfo("0.2.2", text, today="2030-01-01") == text
    bumped = sv._replace_metainfo("0.2.3", text, today="2030-01-01")
    assert bumped == '<release version="0.2.3" date="2030-01-01"/>'


def test_rpm_deb_flathub_replacers() -> None:
    assert sv._replace_rpm("1.2.3", "Name: x\nVersion:        0.2.2\n").endswith(
        "Version:        1.2.3\n"
    )
    deb = "oysterav (0.2.2-1) UNRELEASED; urgency=medium\n"
    assert sv._replace_deb_changelog("0.2.2", deb) == deb
    assert sv._replace_deb_changelog("1.0.0", deb).startswith("oysterav (1.0.0-1) UNRELEASED")
    hub = (
        "        url: https://github.com/asafelobotomy/oysterAV/archive/refs/tags/v0.2.2.tar.gz\n"
        "        sha256: " + "a" * 64 + "\n"
    )
    out = sv._replace_flathub("0.3.0", hub, "b" * 64)
    assert "tags/v0.3.0.tar.gz" in out and "b" * 64 in out
    assert "a" * 64 in sv._replace_flathub("0.3.0", hub, "SKIP")


def test_sync_version_check_passes_and_covers_distro_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    found = sv.current_versions()
    for key in (
        "packaging/arch/.SRCINFO",
        "packaging/rpm/oysterav.spec",
        "packaging/debian/changelog",
        "packaging/oysterav/flatpak/flathub/io.github.asafelobotomy.OysterAV.yml tag",
    ):
        assert key in found
    sv.check(sv.read_version(), strict_sha256=True)
    assert "in sync" in capsys.readouterr().out


def test_check_fails_on_skip_sha_when_strict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgver=0.2.2\nsha256sums=('SKIP')\n", encoding="utf-8")
    monkeypatch.setattr(sv, "PKGBUILD", pkgbuild)
    monkeypatch.setattr(sv, "current_versions", lambda: {})
    with pytest.raises(SystemExit, match="SKIP"):
        sv.check("0.2.2", strict_sha256=True)
    monkeypatch.setattr(sv, "_tag_exists", lambda _v: True)
    monkeypatch.setattr(sv, "_head_is_tag", lambda _v: False)
    with pytest.raises(SystemExit, match="SKIP"):
        sv.check("0.2.2")  # commit after the tag: hash should be pinned
    monkeypatch.setattr(sv, "_head_is_tag", lambda _v: True)
    sv.check("0.2.2")  # release build of the tag commit itself: note only
    with pytest.raises(SystemExit, match="SKIP"):
        sv.check("0.2.2", strict_sha256=True)
    monkeypatch.setattr(sv, "_tag_exists", lambda _v: False)
    monkeypatch.setattr(sv, "_head_is_tag", lambda _v: False)
    sv.check("0.2.2")  # pre-tag release prep: note only


def test_head_is_tag_uses_git(monkeypatch: pytest.MonkeyPatch) -> None:
    revs = {"refs/tags/v9.9.9^{commit}": "abc", "HEAD": "abc"}
    monkeypatch.setattr(sv, "_git_rev", revs.get)
    assert sv._tag_exists("9.9.9") and sv._head_is_tag("9.9.9")
    assert not sv._skip_is_stale("9.9.9")
    revs["HEAD"] = "def"
    assert sv._skip_is_stale("9.9.9")
    assert not sv._tag_exists("1.0.0") and not sv._skip_is_stale("1.0.0")


def test_metainfo_has_no_invalid_oars_ids() -> None:
    meta = PKG / "oysterav" / "flatpak" / "io.github.asafelobotomy.OysterAV.metainfo.xml"
    text = meta.read_text(encoding="utf-8")
    assert "network-internet" not in text and "system-access" not in text
    tool = shutil.which("appstreamcli")
    if tool:
        proc = subprocess.run(
            [tool, "validate", "--no-net", str(meta)], capture_output=True, text=True
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


def test_flathub_pydantic_core_matches_uv_lock() -> None:
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    block = lock.split('name = "pydantic-core"\n', 1)[1].split("[[package]]", 1)[0]
    locked = re.search(r'version = "([^"]+)"', block)
    assert locked
    manifest = (
        PKG / "oysterav" / "flatpak" / "flathub" / "io.github.asafelobotomy.OysterAV.yml"
    ).read_text(encoding="utf-8")
    pins = re.findall(
        r"url: (\S+pydantic_core-([\d.]+)-\S+\.whl)\n\s*sha256: ([0-9a-f]{64})", manifest
    )
    assert len(pins) == 2
    for url, version, sha in pins:
        assert version == locked.group(1)
        assert f'"{url}", hash = "sha256:{sha}"' in block


def test_helper_shebangs_are_isolated() -> None:
    for path in (
        PKG / "arch" / "PKGBUILD.in",
        PKG / "arch" / "PKGBUILD",
        PKG / "rpm" / "oysterav.spec",
        PKG / "debian" / "oyst-helper.in",
    ):
        text = path.read_text(encoding="utf-8")
        assert "#!/usr/bin/python3 -I" in text, path
        assert "#!/usr/bin/env python3" not in text, path


def test_debian_scaffold_consistency() -> None:
    deb = PKG / "debian"
    assert not (deb / "compat").exists()
    assert (deb / "source" / "format").read_text(encoding="utf-8").strip() == "3.0 (quilt)"
    assert "oyst-helper.in" not in (deb / "oysterav.install").read_text(encoding="utf-8")
    rules = (deb / "rules").read_text(encoding="utf-8")
    assert "debian/oysterav/usr/lib/oysterav/oyst-helper" in rules
    assert "not treat this scaffold as upload-ready" in (deb / "README.md").read_text(
        encoding="utf-8"
    )


def test_fpm_after_remove_mirrors_polkit_refresh() -> None:
    script = PKG / "fpm" / "after-remove.sh"
    assert script.stat().st_mode & 0o111
    assert "systemctl reload polkit" in script.read_text(encoding="utf-8")
