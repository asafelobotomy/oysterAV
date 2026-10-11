"""Audit P4: dev-mode helper (user-writable site root) must not get passwordless root."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged.auth_grant import (
    grant_service_lifecycle,
    migrate_grant_on_helper_install,
)
from oyst_core.privileged.auth_grant_scope import format_expires
from oyst_core.privileged.helper_site_trust import (
    helper_untrusted_site_reason,
    parse_helper_site_root,
    untrusted_site_reason,
)
from oyst_core.privileged.install_privileged_helper import HELPER_SCRIPT_WITH_SITE

pytestmark = pytest.mark.security


def _fake_checkout(tmp_path: Path) -> Path:
    site = tmp_path / "checkout"
    (site / "oyst_core").mkdir(parents=True)
    (site / "oyst_core" / "__init__.py").write_text("", encoding="utf-8")
    return site


def test_parse_helper_site_root_roundtrips_template() -> None:
    text = HELPER_SCRIPT_WITH_SITE.format(python="/usr/bin/python3", site_root="/opt/o y'st")
    assert parse_helper_site_root(text) == "/opt/o y'st"
    assert parse_helper_site_root("#!/usr/bin/python3\nfrom x import main\n") is None


def test_user_owned_checkout_is_untrusted(tmp_path: Path) -> None:
    # tmp_path is owned by the (non-root) test user.
    assert untrusted_site_reason(_fake_checkout(tmp_path)) is not None


def test_helper_with_user_site_is_untrusted(tmp_path: Path) -> None:
    helper = tmp_path / "oyst-helper"
    helper.write_text(
        HELPER_SCRIPT_WITH_SITE.format(python="/usr/bin/python3", site_root=str(tmp_path)),
        encoding="utf-8",
    )
    assert helper_untrusted_site_reason(helper)
    assert helper_untrusted_site_reason(tmp_path / "missing") is None


def test_grant_refused_when_helper_embeds_untrusted_site() -> None:
    with (
        patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0),
        patch(
            "oyst_core.privileged.auth_grant.helper_untrusted_site_reason",
            return_value="/home/u/oysterAV is not root-owned",
        ),
        patch("oyst_core.privileged.auth_grant.write_text_nofollow") as write,
    ):
        result = grant_service_lifecycle("alice")
    assert result["ok"] is False
    assert "untrusted" in str(result["message"])
    write.assert_not_called()


@pytest.mark.parametrize("expires", ["past", None])
def test_migrate_revokes_expired_or_undated_grant(tmp_path: Path, expires: str | None) -> None:
    stamp = tmp_path / "usr" / "local" / "share" / "oysterav" / "service-lifecycle.grant"
    stamp.parent.mkdir(parents=True)
    body = "user=alice\nversion=10\n"
    if expires == "past":
        body += f"expires={format_expires(datetime.now(UTC) - timedelta(days=1))}\n"
    stamp.write_text(body, encoding="utf-8")
    rules = tmp_path / "etc" / "polkit-1" / "rules.d" / "49-oysterav-service-lifecycle.rules"
    rules.parent.mkdir(parents=True)
    rules.write_text("legacy YES grant", encoding="utf-8")
    with patch("oyst_core.privileged.auth_grant.os.geteuid", return_value=0):
        result = migrate_grant_on_helper_install(prefix=tmp_path)
    assert result is not None
    assert not rules.exists()
    assert not stamp.exists()
