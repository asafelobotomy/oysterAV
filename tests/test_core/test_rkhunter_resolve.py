"""Tests for rkhunter Resolve planner, overlay merge, and safety gates."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.packs.rkhunter_resolve import (
    apply_overlay_line,
    merge_overlay_text,
    package_owner,
    path_allowed_for_resolve,
    plan_resolve,
    resolve_finding,
    validate_whitelist_option,
)
from oyst_core.privileged.oyst_helper import _build_rkhunter_whitelist_argv
from oyst_core.privileged.runner import CommandResult


def test_plan_script_replacement() -> None:
    plan = plan_resolve(
        "rkhunter-script-replacement",
        path="/usr/bin/egrep",
        message="Warning: The command '/usr/bin/egrep' has been replaced",
    )
    assert plan.option == "SCRIPTWHITELIST"
    assert plan.value == "/usr/bin/egrep"
    assert plan.requires_path


def test_plan_hidden_and_ssh() -> None:
    hidden = plan_resolve(
        "rkhunter-hidden",
        path="/etc/.updated",
        message="Warning: Hidden file found: /etc/.updated",
    )
    assert hidden.option == "ALLOWHIDDENFILE"
    proto = plan_resolve(
        "rkhunter-ssh",
        message="Warning: The SSH configuration option 'Protocol' has not been set.",
    )
    assert proto.option == "ALLOW_SSH_PROT_V1"
    assert proto.value == "2"
    root = plan_resolve(
        "rkhunter-ssh",
        message="Warning: The SSH configuration option 'PermitRootLogin' has not been set.",
    )
    assert root.option == "ALLOW_SSH_ROOT_USER"
    assert root.value == "unset"


def test_plan_rejects_unknown_threat() -> None:
    with pytest.raises(ValueError, match="not resolvable"):
        plan_resolve("rkhunter-warning", path="/tmp/x")


def test_merge_overlay_idempotent_and_replace_ssh(tmp_path: Path) -> None:
    text, changed = merge_overlay_text("", "SCRIPTWHITELIST", "/usr/bin/egrep")
    assert changed
    assert "SCRIPTWHITELIST=/usr/bin/egrep" in text
    text2, changed2 = merge_overlay_text(text, "SCRIPTWHITELIST", "/usr/bin/egrep")
    assert not changed2
    text3, changed3 = merge_overlay_text(text2, "ALLOW_SSH_PROT_V1", "2")
    assert changed3
    text4, changed4 = merge_overlay_text(text3, "ALLOW_SSH_PROT_V1", "2")
    assert not changed4
    apply_overlay_line("ALLOWHIDDENFILE", "/etc/.updated", overlay_path=tmp_path / "wl.conf")
    assert (tmp_path / "wl.conf").read_text(encoding="utf-8").count("ALLOWHIDDENFILE=") == 1


def test_validate_rejects_bad_option_and_path() -> None:
    with pytest.raises(ValueError):
        validate_whitelist_option("DISABLE_TESTS", "all")
    with pytest.raises(ValueError):
        validate_whitelist_option("SCRIPTWHITELIST", "relative")
    with pytest.raises(ValueError):
        validate_whitelist_option("ALLOW_SSH_ROOT_USER", "yes")


def test_path_allowed_known_safe_and_package(tmp_path: Path) -> None:
    stamp = tmp_path / ".updated"
    stamp.write_text("x", encoding="utf-8")
    with patch(
        "oyst_core.packs.rkhunter_resolve_plan.KNOWN_SAFE_HIDDEN",
        frozenset({str(stamp)}),
    ):
        path_allowed_for_resolve(str(stamp), "rkhunter-hidden")
    owned = tmp_path / "owned"
    owned.write_text("x", encoding="utf-8")
    with patch(
        "oyst_core.packs.rkhunter_resolve_plan.package_owner",
        return_value="grep 1.0",
    ):
        path_allowed_for_resolve(str(owned), "rkhunter-script-replacement")
    stranger = tmp_path / "stranger"
    stranger.write_text("y", encoding="utf-8")
    with patch("oyst_core.packs.rkhunter_resolve_plan.package_owner", return_value=None):
        with pytest.raises(ValueError, match="not package-owned"):
            path_allowed_for_resolve(str(stranger), "rkhunter-script-replacement")
        path_allowed_for_resolve(str(stranger), "rkhunter-script-replacement", force=True)


def test_helper_rkhunter_whitelist_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    overlay = tmp_path / "oysterav-whitelist.conf"
    monkeypatch.setattr(
        "oyst_core.packs.rkhunter_overlay.OVERLAY_PATH",
        overlay,
    )
    assert _build_rkhunter_whitelist_argv(["set", "SCRIPTWHITELIST", "/usr/bin/ldd"]) == ["true"]
    assert "SCRIPTWHITELIST=/usr/bin/ldd" in overlay.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="usage"):
        _build_rkhunter_whitelist_argv(["set"])


def test_resolve_finding_dry_run(tmp_path: Path) -> None:
    owned = tmp_path / "egrep"
    owned.write_text("#!/bin/sh\n", encoding="utf-8")
    with patch(
        "oyst_core.packs.rkhunter_resolve_plan.package_owner",
        return_value="grep",
    ):
        result = resolve_finding(
            "rkhunter-script-replacement",
            path=str(owned),
            dry_run=True,
        )
    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["option"] == "SCRIPTWHITELIST"


def test_resolve_finding_calls_helper() -> None:
    with (
        patch(
            "oyst_core.packs.rkhunter_overlay.path_allowed_for_resolve",
        ),
        patch(
            "oyst_core.packs.rkhunter_overlay.run_privileged_helper",
            return_value=CommandResult(0, "ok", ""),
        ) as helper,
    ):
        result = resolve_finding(
            "rkhunter-ssh",
            message="Warning: The SSH configuration option 'Protocol' has not been set.",
        )
    assert result["ok"] is True
    helper.assert_called_once_with(
        "rkhunter-whitelist",
        ["set-many", "ALLOW_SSH_PROT_V1=2"],
        timeout=60,
    )


def test_helper_rkhunter_whitelist_set_many(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay = tmp_path / "oysterav-whitelist.conf"
    monkeypatch.setattr(
        "oyst_core.packs.rkhunter_overlay.OVERLAY_PATH",
        overlay,
    )
    assert _build_rkhunter_whitelist_argv(
        [
            "set-many",
            "SCRIPTWHITELIST=/usr/bin/egrep",
            "ALLOWHIDDENFILE=/etc/.updated",
            "ALLOW_SSH_PROT_V1=2",
        ]
    ) == ["true"]
    text = overlay.read_text(encoding="utf-8")
    assert "SCRIPTWHITELIST=/usr/bin/egrep" in text
    assert "ALLOWHIDDENFILE=/etc/.updated" in text
    assert "ALLOW_SSH_PROT_V1=2" in text


def test_helper_rkhunter_set_disable_tests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.packs.rkhunter_resolve import build_disable_tests_overlay_text

    overlay = tmp_path / "oysterav-defaults.conf"
    monkeypatch.setattr(
        "oyst_core.packs.rkhunter_disable_tests.DEFAULTS_OVERLAY_PATH",
        overlay,
    )
    assert _build_rkhunter_whitelist_argv(["set-disable-tests", "suspscan", "apps"]) == ["true"]
    text = overlay.read_text(encoding="utf-8")
    assert "DISABLE_TESTS=suspscan apps" in text
    assert text == build_disable_tests_overlay_text(["suspscan", "apps"])


def test_resolve_findings_batch_one_helper_call() -> None:
    from oyst_core.packs.rkhunter_resolve import resolve_findings_batch

    findings = [
        {
            "threat_name": "rkhunter-ssh",
            "path": "",
            "message": "Warning: The SSH configuration option 'Protocol' has not been set.",
        },
        {
            "threat_name": "rkhunter-ssh",
            "path": "",
            "message": (
                "Warning: The SSH configuration option 'PermitRootLogin' has not been set."
            ),
        },
    ]
    with patch(
        "oyst_core.packs.rkhunter_overlay.run_privileged_helper",
        return_value=CommandResult(0, "ok", ""),
    ) as helper:
        result = resolve_findings_batch(findings)
    assert result["ok"] is True
    assert result["resolved"] == 2
    helper.assert_called_once_with(
        "rkhunter-whitelist",
        ["set-many", "ALLOW_SSH_PROT_V1=2", "ALLOW_SSH_ROOT_USER=unset"],
        timeout=60,
    )


def test_package_owner_uses_pacman() -> None:
    with (
        patch(
            "oyst_core.packs.rkhunter_resolve_plan.shutil.which",
            side_effect=lambda c: c == "pacman",
        ),
        patch(
            "oyst_core.packs.rkhunter_resolve_plan.subprocess.run",
            return_value=CommandResult(0, "/usr/bin/egrep is owned by grep 3.12", ""),
        ) as run,
    ):
        # subprocess.run returns CompletedProcess-like; mock properly
        run.return_value = type(
            "P",
            (),
            {"returncode": 0, "stdout": "/usr/bin/egrep is owned by grep 3.12\n", "stderr": ""},
        )()
        assert package_owner("/usr/bin/egrep") == "/usr/bin/egrep is owned by grep 3.12"
