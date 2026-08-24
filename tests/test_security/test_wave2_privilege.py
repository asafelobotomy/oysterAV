"""Wave 2 privilege / co-control adversarial coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.privileged.auth_grant import assert_lifecycle_grant_not_stale
from oyst_core.privileged.helper_clamd import _validate_wrapper_cmd
from oyst_core.privileged.helper_validate import _validate_package_name

pytestmark = pytest.mark.security

_SYSTEM_WRAPPER = "/usr/lib/oysterav/oyst-virusevent"


def test_package_name_rejects_non_oysterav() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        _validate_package_name("nginx")
    assert _validate_package_name("clamav") == "clamav"
    assert _validate_package_name("rkhunter") == "rkhunter"


def test_wrapper_cmd_rejects_tmp_and_home() -> None:
    with pytest.raises(ValueError, match="/usr/lib/oysterav"):
        _validate_wrapper_cmd("/tmp/oyst-virusevent")
    with pytest.raises(ValueError, match="/usr/lib/oysterav"):
        _validate_wrapper_cmd("/home/u/.local/share/oysterav/bin/oyst-virusevent")


def test_wrapper_cmd_accepts_root_owned_system(tmp_path: Path) -> None:
    body = "#!/bin/sh\n# oyst-virusevent\n"
    fake = tmp_path / "oyst-virusevent"
    fake.write_text(body, encoding="utf-8")
    fake.chmod(0o755)

    mock_path = MagicMock(spec=Path)
    mock_path.name = "oyst-virusevent"
    mock_path.parts = ("/", "usr", "lib", "oysterav", "oyst-virusevent")
    mock_path.is_symlink.return_value = False
    mock_path.is_file.return_value = True
    mock_st = MagicMock()
    mock_st.st_uid = 0
    mock_st.st_mode = 0o100755
    mock_path.stat.return_value = mock_st
    mock_path.read_text.return_value = body

    with patch("oyst_core.privileged.helper_clamd.Path", return_value=mock_path):
        assert _validate_wrapper_cmd(_SYSTEM_WRAPPER) == _SYSTEM_WRAPPER


def test_wrapper_cmd_rejects_group_writable() -> None:
    body = "#!/bin/sh\n# oyst-virusevent\n"
    mock_path = MagicMock(spec=Path)
    mock_path.name = "oyst-virusevent"
    mock_path.parts = ("/", "usr", "lib", "oysterav", "oyst-virusevent")
    mock_path.is_symlink.return_value = False
    mock_path.is_file.return_value = True
    mock_st = MagicMock()
    mock_st.st_uid = 0
    mock_st.st_mode = 0o100775
    mock_path.stat.return_value = mock_st
    mock_path.read_text.return_value = body

    with (
        patch("oyst_core.privileged.helper_clamd.Path", return_value=mock_path),
        pytest.raises(ValueError, match="group- or world-writable"),
    ):
        _validate_wrapper_cmd(_SYSTEM_WRAPPER)


def test_clamonacc_add_path_rejects_denied_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core import config as cfg_mod
    from oyst_core.config import OysterConfig

    cfg = OysterConfig()
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    monkeypatch.setattr(cfg_mod, "save_config", lambda _c: None)
    pack = ClamonaccPack()
    for denied in ("/usr", "/etc/passwd", "/tmp", "/opt", "/mnt", "/media", "/srv", "/home"):
        with pytest.raises(ValueError, match="denied"):
            pack.add_path(denied)


def test_resolve_helper_path_rejects_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core.privileged import helper as helper_mod

    fake = tmp_path / "oyst-helper"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setattr(
        helper_mod,
        "resolve_installed_helper_path",
        lambda: fake,
    )
    # Non-root-owned binary must not be trusted.
    assert helper_mod.resolve_helper_path() is None
    assert helper_mod._is_trusted_helper_binary(fake) is False


def test_assert_lifecycle_grant_not_stale_fail_closed(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    stamp = tmp_path / "stamp"
    rules.write_text("yes\n", encoding="utf-8")
    expired = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp.write_text(f"user=alice\nexpires={expired}\nversion=10\n", encoding="utf-8")
    with pytest.raises(ValueError, match="expired"):
        assert_lifecycle_grant_not_stale(rules_path=rules, stamp_path=stamp)
    # Interactive path: neither present
    assert_lifecycle_grant_not_stale(
        rules_path=tmp_path / "missing-rules",
        stamp_path=tmp_path / "missing-stamp",
    )
