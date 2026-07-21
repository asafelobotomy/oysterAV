"""Tests for shared scan exclude paths."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from oyst_core.scan_excludes import (
    default_scan_exclude_dirs,
    maldet_ignore_paths_value,
    merged_clamav_exclude_dirs,
)


def test_default_scan_exclude_dirs_include_vault_and_maldet() -> None:
    with (
        patch("oyst_core.scan_excludes.is_full_mode", return_value=False),
        patch(
            "oyst_core.scan_excludes.load_config",
            return_value=type(
                "C",
                (),
                {
                    "vault_path": lambda self: Path("/home/u/.local/share/oysterav/quarantine"),
                    "scan": type("S", (), {"exclude_dirs": []})(),
                },
            )(),
        ),
        patch(
            "oyst_core.scan_excludes.data_dir",
            return_value=Path("/home/u/.local/share/oysterav"),
        ),
    ):
        paths = default_scan_exclude_dirs()
    joined = " ".join(paths)
    assert "quarantine" in joined
    assert "/usr/local/maldetect/sigs" in paths
    assert maldet_ignore_paths_value()


def test_merged_clamav_exclude_dirs_dedupes_config() -> None:
    with (
        patch("oyst_core.scan_excludes.is_full_mode", return_value=False),
        patch(
            "oyst_core.scan_excludes.load_config",
            return_value=type(
                "C",
                (),
                {
                    "vault_path": lambda self: Path("/v"),
                    "scan": type(
                        "S",
                        (),
                        {"exclude_dirs": ["/usr/local/maldetect/sigs", "/custom"]},
                    )(),
                },
            )(),
        ),
        patch("oyst_core.scan_excludes.data_dir", return_value=Path("/data")),
    ):
        merged = merged_clamav_exclude_dirs()
    assert merged.count("/usr/local/maldetect/sigs") == 1
    assert "/custom" in merged
