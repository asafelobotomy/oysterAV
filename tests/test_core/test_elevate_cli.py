"""Tests for Polkit-elevated oyst-cli bootstrap (helper install / auth grant)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.privileged.elevate_cli import (
    _validate_elevated_argv,
    grant_service_lifecycle_elevated,
    install_helper_elevated,
    revoke_service_lifecycle_elevated,
    run_elevated_oyst_cli,
)
from oyst_core.privileged.runner import CommandResult


def test_validate_elevated_argv_allows_install() -> None:
    assert _validate_elevated_argv(["install-privileged-helper", "--json"]) == [
        "install-privileged-helper",
        "--json",
    ]


def test_validate_elevated_argv_allows_grant_with_user() -> None:
    assert _validate_elevated_argv(
        ["auth", "grant-service-lifecycle", "--user", "alice", "--json"],
    ) == [
        "auth",
        "grant-service-lifecycle",
        "--user",
        "alice",
        "--confirm",
        "--json",
    ]
    assert _validate_elevated_argv(["auth", "revoke-service-lifecycle", "--json"]) == [
        "auth",
        "revoke-service-lifecycle",
        "--confirm",
        "--json",
    ]


def test_validate_elevated_argv_rejects_shell() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        _validate_elevated_argv(["firewall", "ufw", "enable"])
    with pytest.raises(ValueError, match="invalid username"):
        _validate_elevated_argv(
            ["auth", "grant-service-lifecycle", "--user", "alice;rm", "--json"],
        )


def test_run_elevated_oyst_cli_uses_pkexec_when_not_root() -> None:
    mock_proc = MagicMock(returncode=0, stdout='{"ok": true}', stderr="")
    with (
        patch("oyst_core.privileged.elevate_cli.os.geteuid", return_value=1000),
        patch("oyst_core.privileged.elevate_cli.is_flatpak", return_value=False),
        patch(
            "oyst_core.privileged.elevate_cli.resolve_oyst_cli_path",
            return_value="/usr/bin/oyst-cli",
        ),
        patch("oyst_core.privileged.elevate_cli.which", return_value="/usr/bin/pkexec"),
        patch("oyst_core.privileged.elevate_cli.subprocess.run", return_value=mock_proc) as run,
    ):
        res = run_elevated_oyst_cli(["install-privileged-helper", "--json"])
    assert res.returncode == 0
    run.assert_called_once()
    cmd = run.call_args[0][0]
    assert cmd == [
        "/usr/bin/pkexec",
        "/usr/bin/oyst-cli",
        "install-privileged-helper",
        "--json",
    ]


def test_run_elevated_oyst_cli_flatpak_uses_host_pkexec() -> None:
    mock_proc = MagicMock(returncode=0, stdout='{"ok": true}', stderr="")
    with (
        patch("oyst_core.privileged.elevate_cli.os.geteuid", return_value=1000),
        patch("oyst_core.privileged.elevate_cli.is_flatpak", return_value=True),
        patch(
            "oyst_core.privileged.elevate_cli._host_oyst_cli_for_flatpak",
            return_value="/usr/bin/oyst-cli",
        ),
        patch("oyst_core.privileged.elevate_cli.which", return_value="/usr/bin/flatpak-spawn"),
        patch("oyst_core.privileged.elevate_cli.subprocess.run", return_value=mock_proc) as run,
    ):
        res = run_elevated_oyst_cli(["install-privileged-helper", "--json"])
    assert res.returncode == 0
    cmd = run.call_args[0][0]
    assert cmd[:4] == [
        "/usr/bin/flatpak-spawn",
        "--host",
        "pkexec",
        "/usr/bin/oyst-cli",
    ]


def test_install_helper_elevated_as_root_calls_install_directly() -> None:
    with (
        patch("oyst_core.privileged.elevate_cli.os.geteuid", return_value=0),
        patch(
            "oyst_core.privileged.install_privileged_helper.install_privileged_helper",
            return_value={
                "ok": True,
                "message": "Installed",
                "helper_path": "/h",
                "polkit_path": "/p",
            },
        ),
        patch(
            "oyst_core.privileged.install_privileged_helper.helper_status",
            return_value={"installed": True, "policy_current": True},
        ),
        patch("oyst_core.audit.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        result = install_helper_elevated()
    assert result["ok"] is True
    assert result["helper"]["installed"] is True


def test_grant_revoke_elevated_via_pkexec() -> None:
    with (
        patch("oyst_core.privileged.elevate_cli.os.geteuid", return_value=1000),
        patch(
            "oyst_core.privileged.elevate_cli.run_elevated_oyst_cli",
            return_value=CommandResult(0, '{"ok": true, "granted_user": "bob"}', ""),
        ),
        patch(
            "oyst_core.privileged.auth_grant.auth_status",
            return_value={"granted": True, "granted_user": "bob"},
        ),
        patch("oyst_core.audit.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        granted = grant_service_lifecycle_elevated("bob")
    assert granted["ok"] is True
    assert granted["service_lifecycle"]["granted"] is True

    with (
        patch("oyst_core.privileged.elevate_cli.os.geteuid", return_value=1000),
        patch(
            "oyst_core.privileged.elevate_cli.run_elevated_oyst_cli",
            return_value=CommandResult(0, '{"ok": true}', ""),
        ),
        patch(
            "oyst_core.privileged.auth_grant.auth_status",
            return_value={"granted": False},
        ),
        patch("oyst_core.audit.SecurityAudit") as audit_cls,
    ):
        audit_cls.return_value.log = MagicMock()
        revoked = revoke_service_lifecycle_elevated()
    assert revoked["ok"] is True
