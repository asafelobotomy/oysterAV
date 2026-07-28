"""Wave 2 privilege / co-control adversarial coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.privileged.auth_grant import assert_lifecycle_grant_not_stale
from oyst_core.privileged.helper_clamd import _validate_wrapper_cmd
from oyst_core.privileged.helper_validate import _validate_package_name

pytestmark = pytest.mark.security


def test_package_name_rejects_non_oysterav() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        _validate_package_name("nginx")
    assert _validate_package_name("clamav") == "clamav"
    assert _validate_package_name("rkhunter") == "rkhunter"


def test_wrapper_cmd_rejects_tmp_and_requires_suffix() -> None:
    with pytest.raises(ValueError, match="under"):
        _validate_wrapper_cmd("/tmp/oyst-virusevent")
    ok = "/home/u/.local/share/oysterav/bin/oyst-virusevent"
    assert _validate_wrapper_cmd(ok) == ok


def test_wrapper_cmd_rejects_group_writable(tmp_path: Path) -> None:
    dest = tmp_path / ".local" / "share" / "oysterav" / "bin" / "oyst-virusevent"
    dest.parent.mkdir(parents=True)
    dest.write_text("#!/bin/sh\n# oyst-virusevent\n", encoding="utf-8")
    dest.chmod(0o775)
    # Path must match allowlisted suffix shape — use real home-shaped path via symlink? 
    # Validate on a constructed path that ends with the required suffix.
    home_shaped = Path.home() / ".local" / "share" / "oysterav" / "bin" / "oyst-virusevent"
    home_shaped.parent.mkdir(parents=True, exist_ok=True)
    home_shaped.write_text("#!/bin/sh\n# oyst-virusevent\n", encoding="utf-8")
    home_shaped.chmod(0o775)
    try:
        with pytest.raises(ValueError, match="group- or world-writable"):
            _validate_wrapper_cmd(str(home_shaped))
    finally:
        home_shaped.chmod(0o755)
        home_shaped.unlink(missing_ok=True)


def test_clamonacc_add_path_rejects_denied_prefixes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core import config as cfg_mod
    from oyst_core.config import OysterConfig

    cfg = OysterConfig()
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    monkeypatch.setattr(cfg_mod, "save_config", lambda _c: None)
    pack = ClamonaccPack()
    with pytest.raises(ValueError, match="denied"):
        pack.add_path("/usr")
    with pytest.raises(ValueError, match="denied"):
        pack.add_path("/etc/passwd")


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
