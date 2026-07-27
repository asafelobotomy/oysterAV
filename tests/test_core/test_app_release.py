"""GitHub Releases oysterAV version checks."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from oyst_core.app_release import (
    check_app_update,
    normalize_tag,
    parse_semver,
    version_is_newer,
)


def test_parse_and_compare_semver() -> None:
    assert parse_semver("v0.2.1") == (0, 2, 1)
    assert parse_semver("0.2.0") == (0, 2, 0)
    assert parse_semver("nope") is None
    assert normalize_tag("v0.2.1") == "0.2.1"
    assert version_is_newer("0.2.1", "0.2.0") is True
    assert version_is_newer("0.2.0", "0.2.0") is False
    assert version_is_newer("0.1.9", "0.2.0") is False


def test_check_app_update_newer(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    payload = {
        "tag_name": "v0.9.9",
        "name": "0.9.9",
        "html_url": "https://github.com/asafelobotomy/oysterAV/releases/tag/v0.9.9",
    }
    with patch("oyst_core.app_release._fetch_url", return_value=json.dumps(payload)):
        result = check_app_update(current="0.2.1", force=True)
    assert result["ok"] is True
    assert result["update"] is not None
    assert result["update"]["kind"] == "app"
    assert result["update"]["available"] == "0.9.9"
    assert result["update"]["current"] == "0.2.1"
    assert "releases/tag/v0.9.9" in result["update"]["url"]


def test_check_app_update_up_to_date(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    payload = {
        "tag_name": "v0.2.1",
        "html_url": "https://github.com/asafelobotomy/oysterAV/releases/tag/v0.2.1",
    }
    with patch("oyst_core.app_release._fetch_url", return_value=json.dumps(payload)):
        result = check_app_update(current="0.2.1", force=True)
    assert result["ok"] is True
    assert result["update"] is None
    assert "up to date" in result["message"]


def test_check_app_update_network_error(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    with patch("oyst_core.app_release._fetch_url", side_effect=TimeoutError("slow")):
        result = check_app_update(current="0.2.1", force=True)
    assert result["ok"] is False
    assert result["update"] is None
