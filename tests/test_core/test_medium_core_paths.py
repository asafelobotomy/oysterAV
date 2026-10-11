"""Regression: anchored exclude dirs, install-dir-only guards, exact VirusEvent path."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.config_access import _parse_exclude_dirs_csv
from oyst_core.models import Finding, FindingSeverity
from oyst_core.packs import maldet_parse
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.scan_excludes import clamav_exclude_dir_regex
from oyst_core.virusevent import ENV_FILENAME, ENV_VIRUSNAME, handle_virusevent


@pytest.mark.parametrize(
    ("excl", "path", "hit"),
    [
        ("/opt", "/opt", True),
        ("/opt", "/opt/app/x", True),
        ("/opt", "/home/u/Downloads/options", False),
        ("/opt", "/optional", False),
        ("/home/u/.cache", "/home/u/.cache/x", True),
        ("/home/u/.cache", "/home/u/Xcache", False),
    ],
)
def test_exclude_dir_regex_is_anchored(excl: str, path: str, hit: bool) -> None:
    assert bool(re.search(clamav_exclude_dir_regex(excl), path)) is hit


def test_append_exclude_dirs_emits_anchored_and_drops_relative() -> None:
    with patch(
        "oyst_core.packs.clamav.merged_clamav_exclude_dirs",
        return_value=["/opt", ".", "cache"],
    ):
        argv: list[str] = []
        ClamAVPack()._append_exclude_dirs(argv)
    assert argv == ["--exclude-dir=^/opt(/|$)"]


@pytest.mark.parametrize("bad", [".", "cache", "./x", "Downloads/tmp"])
def test_exclude_dirs_config_requires_absolute(bad: str) -> None:
    with pytest.raises(ValueError, match="absolute"):
        _parse_exclude_dirs_csv(bad)


def test_exclude_dirs_config_accepts_absolute_and_home() -> None:
    assert _parse_exclude_dirs_csv("/opt, ~/.cache") == ["/opt", "~/.cache"]


def test_maldet_sigs_filter_only_real_install(tmp_path: Path) -> None:
    runtime = tmp_path / "rt" / "maldetect"
    with patch.object(maldet_parse, "runtime_maldet_prefix", return_value=runtime):
        assert maldet_parse.is_maldet_self_signature_path("/usr/local/maldetect/sigs/hex.dat")
        assert maldet_parse.is_maldet_self_signature_path(str(runtime / "sigs" / "md5v2.dat"))
        fake = tmp_path / "Downloads" / "maldetect" / "sigs" / "dropper"
        assert not maldet_parse.is_maldet_self_signature_path(str(fake))
        f = Finding(
            pack="maldet",
            path=str(fake),
            threat_name="x",
            severity=FindingSeverity.HIGH,
            message="",
        )
        assert maldet_parse.filter_malware_findings([f]) == [f]


def test_virusevent_keeps_exact_filename(tmp_path: Path) -> None:
    victim = tmp_path / " bad.bin "
    victim.write_bytes(b"x")
    stripped = tmp_path / "bad.bin"
    stripped.write_bytes(b"innocent")
    env = {ENV_FILENAME: str(victim), ENV_VIRUSNAME: "Eicar"}
    with (
        patch("oyst_core.virusevent.EventLog"),
        patch("oyst_core.virusevent.SecurityAudit"),
        patch("oyst_core.virusevent.QuarantineVault") as vault_cls,
        patch("oyst_core.virusevent._notify"),
        patch("oyst_core.virusevent.load_config"),
    ):
        vault_cls.return_value.add = MagicMock()
        result = handle_virusevent(env=env, quarantine=True)
    assert result["path"] == str(victim)
    vault_cls.return_value.add.assert_called_once_with(str(victim), "Eicar")


def test_virusevent_rejects_empty_filename() -> None:
    assert handle_virusevent(env={ENV_FILENAME: ""}, quarantine=False)["ok"] is False
