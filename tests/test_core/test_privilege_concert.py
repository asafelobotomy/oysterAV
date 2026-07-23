"""Privilege concert plan / preflight / recipe unit tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.rkhunter_resolve_preview import preview_rkhunter_resolve_plan
from oyst_core.privilege import (
    PRIVILEGED_SCAN_PACKS,
    build_harden_plan,
    build_install_packs_plan,
    build_rkhunter_resolve_plan,
    build_scan_privileged_plan,
    build_setup_plan,
    build_update_all_plan,
    pack_priority,
    preflight_body,
    preflight_dict,
    run_privilege_concert,
    sort_pack_names,
    split_scan_packs,
)
from oyst_core.privileged.helper_concert import run_concert, run_scan_concert_alias
from oyst_core.privileged.helper_scan_concert import run_scan_privileged_steps


def test_build_scan_privileged_plan_rejects_unknown_packs() -> None:
    with pytest.raises(ValueError, match="unknown scan pack"):
        build_scan_privileged_plan(
            ["clamav", "not-a-pack"],
            job_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )


def test_split_scan_packs_orders_privileged_first() -> None:
    priv, local = split_scan_packs(["clamav", "lynis", "rkhunter", "maldet", "chkrootkit"])
    assert priv == ["rkhunter", "chkrootkit", "lynis"]
    assert local == ["clamav", "maldet"]


def test_build_scan_privileged_plan_preflight() -> None:
    plan = build_scan_privileged_plan(
        ["clamav", "rkhunter", "unhide"],
        job_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    assert plan.needs_elevation
    assert plan.argv1 == "scan-concert"
    assert plan.recipe == "scan-privileged"
    assert [s.id for s in plan.privileged_steps] == ["rkhunter", "unhide"]
    assert [s.id for s in plan.local_steps] == ["clamav"]
    body = preflight_body(plan)
    assert "Administrator authentication is required once" in body
    assert "rkhunter" in body.lower() or "rootkit" in body.lower()
    assert "ClamAV" in body
    data = preflight_dict(plan)
    assert data["needs_elevation"] is True
    assert "--job-id=" in "".join(plan.to_helper_argv())
    assert "--pack=rkhunter" in plan.to_helper_argv()
    assert "--rkh-overlay" in plan.to_helper_argv()


def test_build_scan_plan_no_elevation_for_malware_only() -> None:
    plan = build_scan_privileged_plan(["clamav", "maldet"], job_id="preview")
    assert not plan.needs_elevation
    assert plan.helper_argv == []


def test_setup_and_harden_plans() -> None:
    setup = build_setup_plan(["--install=clamav:official"])
    assert setup.needs_elevation and setup.argv1 == "setup-concert"
    harden = build_harden_plan(["--fdpass"])
    assert harden.needs_elevation and harden.argv1 == "setup-harden"
    empty = build_setup_plan([])
    assert not empty.needs_elevation


def test_run_privilege_concert_skips_without_elevation() -> None:
    plan = build_scan_privileged_plan(["clamav"], job_id="preview")
    assert run_privilege_concert(plan) == []


def test_run_privilege_concert_calls_helper() -> None:
    plan = build_scan_privileged_plan(["rkhunter"], job_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    mock_res = MagicMock(
        returncode=0,
        stdout='{"steps":[{"step":"scan-rkhunter","ok":true}]}',
        stderr="",
    )
    with (
        patch("oyst_core.privilege.run.run_privileged_helper", return_value=mock_res) as helper,
        patch("oyst_core.privilege.run.SecurityAudit"),
    ):
        steps = run_privilege_concert(plan)
    helper.assert_called_once()
    assert helper.call_args[0][0] == "scan-concert"
    assert steps[0]["step"] == "scan-rkhunter"


def test_scan_concert_rejects_bad_job_and_pack() -> None:
    with pytest.raises(ValueError, match="job id"):
        run_scan_privileged_steps(["--job-id=bad!", "--pack=rkhunter"])
    with pytest.raises(ValueError, match="requires --pack"):
        run_scan_privileged_steps(["--job-id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    with pytest.raises(ValueError, match="unknown scan-concert pack"):
        run_scan_privileged_steps(
            [
                "--job-id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "--pack=not-a-pack",
            ],
        )
    with pytest.raises(ValueError, match="unknown concert recipe"):
        run_concert(["--recipe=not-a-recipe"])


def test_scan_concert_alias_dispatches() -> None:
    argv = [
        "--job-id=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "--pack=rkhunter",
    ]
    with patch(
        "oyst_core.privileged.helper_concert.run_scan_concert",
        return_value=0,
    ) as run_scan:
        assert run_scan_concert_alias(argv) == 0
    run_scan.assert_called_once()
    assert PRIVILEGED_SCAN_PACKS == frozenset({"rkhunter", "chkrootkit", "unhide", "lynis"})


def test_build_rkhunter_resolve_plan_preflight() -> None:
    plan = build_rkhunter_resolve_plan(
        [("ALLOW_SSH_PROT_V1", "2"), ("SCRIPTWHITELIST", "/usr/bin/egrep")],
    )
    assert plan.needs_elevation
    assert plan.recipe == "resolve-rkhunter"
    assert plan.argv1 == "rkhunter-whitelist"
    assert plan.to_helper_argv()[0] == "set-many"
    assert "ALLOW_SSH_PROT_V1=2" in plan.to_helper_argv()
    body = preflight_body(plan)
    assert "Administrator authentication is required once" in body
    assert "sshd_config" in body
    assert "whitelist" in body.lower()


def test_preview_rkhunter_resolve_plan_ssh() -> None:
    findings = [
        {
            "threat_name": "rkhunter-ssh",
            "path": "",
            "message": "Warning: The SSH configuration option 'Protocol' has not been set.",
        },
    ]
    plan, errors = preview_rkhunter_resolve_plan(findings)
    assert not errors
    assert plan is not None
    assert plan.argv1 == "rkhunter-whitelist"
    assert "ALLOW_SSH_PROT_V1=2" in plan.to_helper_argv()


def test_sort_pack_names_priority_order() -> None:
    ordered = sort_pack_names(["lynis", "clamav", "rkhunter", "maldet"])
    assert ordered[0] == "clamav"
    assert ordered.index("rkhunter") < ordered.index("lynis")
    assert pack_priority("clamav") < pack_priority("rkhunter") < pack_priority("lynis")


def test_build_install_packs_plan_orders_and_elevates() -> None:
    plan = build_install_packs_plan(
        ["lynis", "clamav", "rkhunter"],
        elevate=True,
    )
    assert plan.needs_elevation
    assert plan.disclosure_only
    assert plan.argv1 == ""
    assert plan.helper_argv == []
    assert [s.id for s in plan.ordered_privileged_steps()] == [
        "install-clamav",
        "install-rkhunter",
        "install-lynis",
    ]
    full = build_install_packs_plan(["clamav"], elevate=False)
    assert not full.needs_elevation
    assert full.disclosure_only
    assert full.local_steps
    with pytest.raises(ValueError, match="disclosure-only"):
        run_privilege_concert(plan)


def test_build_update_all_plan_preflight_labels() -> None:
    plan = build_update_all_plan(
        official_packages=["clamav", "rkhunter"],
        family="arch",
        include_rkh_update=True,
        include_rkh_propupd=True,
    )
    assert plan.needs_elevation
    assert not plan.disclosure_only
    assert plan.argv1 == "update-concert"
    assert "--upgrade=clamav,rkhunter" in plan.helper_argv
    assert "--rkh-update" in plan.helper_argv
    assert "--rkh-propupd" in plan.helper_argv
    body = preflight_body(plan)
    assert "clamav" in body or "Upgrade packages" in body
    assert "freshclam" in body.lower() or "ClamAV" in body
    no_pkgs = build_update_all_plan()
    assert not no_pkgs.needs_elevation
    assert no_pkgs.local_steps
    assert no_pkgs.disclosure_only


def test_harden_plan_step_ids_priority() -> None:
    plan = build_harden_plan(
        ["--fdpass"],
        step_ids=["firewall-ensure", "harden-fdpass", "harden-clamd"],
    )
    ids = [s.id for s in plan.ordered_privileged_steps()]
    assert ids.index("harden-clamd") < ids.index("harden-fdpass")
    assert ids.index("harden-fdpass") < ids.index("firewall-ensure")
