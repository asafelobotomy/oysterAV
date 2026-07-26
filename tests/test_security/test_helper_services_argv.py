"""Adversarial corpora for systemctl / fail2ban / maldet / rkhunter builders."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oyst_core.privileged.helper_fail2ban import _build_fail2ban_argv
from oyst_core.privileged.helper_services import (
    _build_maldet_config_argv,
    _build_rkhunter_whitelist_argv,
    _build_systemctl_argv,
    _build_systemctl_up_argv,
)
from tests.test_security.corpora import (
    FAIL2BAN_REJECT_CASES,
    SYSTEMCTL_OK_CASES,
    SYSTEMCTL_REJECT_CASES,
    Case,
)

pytestmark = pytest.mark.security


@pytest.mark.parametrize("case", SYSTEMCTL_REJECT_CASES, ids=lambda c: c.id)
def test_build_systemctl_argv_rejects(case: Case) -> None:
    assert case.expect.kind == "value_error"
    with pytest.raises(ValueError):
        _build_systemctl_argv(list(case.payload))  # type: ignore[arg-type]


@pytest.mark.parametrize("case", SYSTEMCTL_OK_CASES, ids=lambda c: c.id)
def test_build_systemctl_argv_safe_shape(case: Case) -> None:
    argv = _build_systemctl_argv(list(case.payload))  # type: ignore[arg-type]
    assert case.expect.substr is None or case.expect.substr in argv[0]
    assert argv == ["systemctl", "restart", "fail2ban"]
    assert _build_systemctl_argv(["enable-now", "fail2ban"]) == [
        "systemctl",
        "enable",
        "--now",
        "fail2ban",
    ]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["stop", "maldet"],
        ["restart", "fail2ban"],
        ["enable-now", "firewalld"],
        ["start", "maldet;id"],
    ],
)
def test_build_systemctl_up_argv_rejects(argv: list[str]) -> None:
    with patch("oyst_core.privileged.helper_services.assert_lifecycle_grant_not_stale"):
        with pytest.raises(ValueError):
            _build_systemctl_up_argv(argv)


def test_build_systemctl_up_argv_accepts_maldet() -> None:
    with patch("oyst_core.privileged.helper_services.assert_lifecycle_grant_not_stale"):
        argv = _build_systemctl_up_argv(["start", "maldet"])
    assert argv[0] == "systemctl"
    assert "maldet" in argv


def test_systemctl_up_fails_closed_on_stale_grant() -> None:
    with patch(
        "oyst_core.privileged.helper_services.assert_lifecycle_grant_not_stale",
        side_effect=ValueError("service-lifecycle grant expired"),
    ):
        with pytest.raises(ValueError, match="expired"):
            _build_systemctl_up_argv(["start", "maldet"])


@pytest.mark.parametrize("case", FAIL2BAN_REJECT_CASES, ids=lambda c: c.id)
def test_build_fail2ban_argv_rejects(case: Case) -> None:
    assert case.expect.kind == "value_error"
    with pytest.raises(ValueError):
        _build_fail2ban_argv(list(case.payload))  # type: ignore[arg-type]


def test_build_fail2ban_argv_safe_shapes() -> None:
    assert _build_fail2ban_argv(["banned"])[0] == "fail2ban-client"
    assert _build_fail2ban_argv(["unban", "192.0.2.1"]) == [
        "fail2ban-client",
        "unban",
        "192.0.2.1",
    ]
    assert _build_fail2ban_argv(["reload"]) == ["fail2ban-client", "reload"]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["set-monitor-mode"],
        ["set-monitor-mode", "relative"],
        ["set-monitor-mode", "/tmp/evil;id"],
        ["set-monitor-mode", "/tmp/../etc/passwd"],
        ["start-monitor", "users;id"],
        ["unknown"],
    ],
)
def test_build_maldet_config_rejects_before_side_effects(argv: list[str]) -> None:
    with (
        patch("oyst_core.privileged.helper_services.assert_lifecycle_grant_not_stale"),
        patch(
            "oyst_core.privileged.helper_services._apply_maldet_monitor_mode",
        ) as apply,
        pytest.raises(ValueError),
    ):
        _build_maldet_config_argv(argv)
    apply.assert_not_called()


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["set"],
        ["set", "ALLOWHIDDENDIR"],
        ["set-many"],
        ["set-many", "NOEQUALS"],
        ["weird"],
    ],
)
def test_build_rkhunter_whitelist_rejects_shape(argv: list[str]) -> None:
    with (
        patch("oyst_core.privileged.helper_services.apply_overlay_line") as one,
        patch("oyst_core.privileged.helper_services.apply_overlay_lines") as many,
        patch("oyst_core.privileged.helper_services.apply_disable_tests_overlay") as dis,
        pytest.raises(ValueError),
    ):
        _build_rkhunter_whitelist_argv(argv)
    one.assert_not_called()
    many.assert_not_called()
    dis.assert_not_called()
