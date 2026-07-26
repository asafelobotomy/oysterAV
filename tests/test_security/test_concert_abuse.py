"""Privilege concert workflow abuse matrix (ASVS V11.1)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oyst_core.privilege.recipes import (
    build_install_packs_plan,
    build_scan_privileged_plan,
)
from oyst_core.privilege.run import run_privilege_concert
from oyst_core.privileged.helper_concert import run_concert
from oyst_core.privileged.helper_fw_lifecycle import _family_install_argv
from oyst_core.privileged.helper_scan_concert import (
    _validate_job_id,
    run_scan_concert,
)
from oyst_core.privileged.helper_services import _build_rkhunter_whitelist_argv
from oyst_core.privileged.helper_update_concert import run_update_concert
from tests.test_security.corpora import CONCERT_ABUSE_CASES, Case

pytestmark = pytest.mark.security

_JOB = "abcdef01-2345-6789-abcd-ef0123456789"


def _cases(*surfaces: str) -> tuple[Case, ...]:
    return tuple(c for c in CONCERT_ABUSE_CASES if c.surface in surfaces)


@pytest.mark.parametrize("case", _cases("helper_concert"), ids=lambda c: c.id)
def test_concert_recipe_abuse(case: Case) -> None:
    assert case.expect.kind == "value_error"
    with pytest.raises(ValueError):
        run_concert(list(case.payload))  # type: ignore[arg-type]


@pytest.mark.parametrize("case", _cases("privilege_plan"), ids=lambda c: c.id)
def test_scan_plan_unknown_pack(case: Case) -> None:
    assert case.expect.kind == "value_error"
    payload = case.payload
    assert isinstance(payload, dict)
    with pytest.raises(ValueError):
        build_scan_privileged_plan(
            list(payload["packs"]),  # type: ignore[arg-type]
            job_id=str(payload["job_id"]),
        )


@pytest.mark.parametrize(
    "case",
    _cases("helper_scan_concert"),
    ids=lambda c: c.id,
)
def test_scan_concert_abuse(case: Case) -> None:
    payload = case.payload
    if case.expect.kind == "value_error":
        assert isinstance(payload, str)
        with pytest.raises(ValueError):
            _validate_job_id(payload)
        return
    assert case.expect.kind == "usage_exit_2"
    assert isinstance(payload, list)
    assert run_scan_concert(payload) == 2


@pytest.mark.parametrize("case", _cases("helper_update_concert"), ids=lambda c: c.id)
def test_update_concert_empty(case: Case) -> None:
    assert case.expect.kind == "usage_exit_2"
    assert run_update_concert(list(case.payload)) == 2  # type: ignore[arg-type]


@pytest.mark.parametrize("case", _cases("helper_fw_install"), ids=lambda c: c.id)
def test_install_pkg_injection(case: Case) -> None:
    assert case.expect.kind == "value_error"
    family, pkgs = case.payload  # type: ignore[misc]
    with pytest.raises(ValueError):
        _family_install_argv(family, pkgs)


@pytest.mark.parametrize(
    "case",
    _cases("helper_rkhunter_whitelist"),
    ids=lambda c: c.id,
)
def test_rkhunter_whitelist_resolve_abuse(case: Case) -> None:
    assert case.expect.kind == "value_error"
    with (
        patch("oyst_core.privileged.helper_services.apply_overlay_line") as one,
        patch("oyst_core.privileged.helper_services.apply_overlay_lines") as many,
        patch("oyst_core.privileged.helper_services.apply_disable_tests_overlay") as dis,
        pytest.raises(ValueError),
    ):
        _build_rkhunter_whitelist_argv(list(case.payload))  # type: ignore[arg-type]
    one.assert_not_called()
    many.assert_not_called()
    dis.assert_not_called()


@pytest.mark.parametrize("case", _cases("privilege_run"), ids=lambda c: c.id)
def test_disclosure_only_refuses_concert_run(case: Case) -> None:
    assert case.expect.kind == "value_error"
    plan = build_install_packs_plan(["clamav"])
    assert plan.disclosure_only is True
    with pytest.raises(ValueError, match=case.expect.substr or "disclosure"):
        run_privilege_concert(plan)


def test_cross_concert_scan_rejects_setup_flags() -> None:
    """Setup-style flags must not satisfy scan-concert pack requirements."""
    rc = run_scan_concert([f"--job-id={_JOB}", "--family=arch", "--install=ufw"])
    assert rc == 2


def test_scan_plan_orders_privileged_before_local() -> None:
    plan = build_scan_privileged_plan(
        ["clamav", "rkhunter", "lynis"],
        job_id=_JOB,
    )
    ids = [s.id for s in plan.privileged_steps]
    assert ids == ["rkhunter", "lynis"]
    assert [s.id for s in plan.local_steps] == ["clamav"]
    # Forged duplicate packs normalize; no shell metachar in argv
    for arg in plan.helper_argv:
        assert ";" not in arg
        assert "|" not in arg
