"""Privileged helper env scrub + argc edge cases (PwnKit-inspired)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.privileged.oyst_helper import _secure_exec_env, run_helper_argv
from oyst_core.privileged.runner import (
    CommandResult,
    command_scrubbed_env,
    pkexec_scrubbed_env,
    run_install_command,
    scrubbed_env_for_argv,
    user_session_scrubbed_env,
)
from tests.test_security.corpora import HELPER_ARGC_CASES, Case

pytestmark = pytest.mark.security

_SECRET_KEYS = (
    "OYST_TOKEN",
    "SSH_AUTH_SOCK",
    "AWS_SECRET_ACCESS_KEY",
    "LD_PRELOAD",
    "PYTHONPATH",
)


@pytest.fixture
def planted_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _SECRET_KEYS:
        monkeypatch.setenv(key, f"secret-value-for-{key}")
    monkeypatch.setenv("PATH", "/evil/bin:/usr/bin")


def _assert_scrubbed(env: dict[str, str], *, allow_session: bool = False) -> None:
    for key in _SECRET_KEYS:
        assert key not in env, f"{key} must not leak into scrubbed env"
    assert env.get("PATH", "").startswith("/usr/bin")
    if not allow_session:
        assert "SSH_AUTH_SOCK" not in env


def test_pkexec_scrubbed_env_drops_secrets(planted_secrets: None) -> None:
    env = pkexec_scrubbed_env()
    _assert_scrubbed(env)


def test_command_scrubbed_env_drops_secrets(planted_secrets: None) -> None:
    env = command_scrubbed_env()
    _assert_scrubbed(env)
    assert "DISPLAY" not in env
    assert "DBUS_SESSION_BUS_ADDRESS" not in env


def test_user_session_scrubbed_env_still_drops_secrets(
    planted_secrets: None,
) -> None:
    env = user_session_scrubbed_env()
    for key in ("OYST_TOKEN", "AWS_SECRET_ACCESS_KEY", "LD_PRELOAD", "PYTHONPATH"):
        assert key not in env
    assert env.get("PATH", "").startswith("/usr/bin")


def test_scrubbed_env_for_argv_systemctl_user(planted_secrets: None) -> None:
    env = scrubbed_env_for_argv(["systemctl", "--user", "status"])
    for key in ("OYST_TOKEN", "AWS_SECRET_ACCESS_KEY", "LD_PRELOAD"):
        assert key not in env


def test_secure_exec_env_drops_secrets(planted_secrets: None) -> None:
    env = _secure_exec_env()
    _assert_scrubbed(env)
    assert env["HOME"] == "/root"


def test_helper_fw_lifecycle_secure_env(planted_secrets: None) -> None:
    from oyst_core.privileged.helper_fw_lifecycle import _secure_env

    env = _secure_env()
    _assert_scrubbed(env)


def test_helper_scan_concert_secure_env(planted_secrets: None) -> None:
    from oyst_core.privileged.helper_scan_concert import _secure_env

    env = _secure_env()
    _assert_scrubbed(env)


@pytest.mark.parametrize("case", HELPER_ARGC_CASES, ids=lambda c: c.id)
def test_run_helper_argv_argc_edges(case: Case, capsys: pytest.CaptureFixture[str]) -> None:
    assert case.expect.kind == "usage_exit_2"
    rc = run_helper_argv(list(case.payload))  # type: ignore[arg-type]
    assert rc == 2
    err = capsys.readouterr().err
    assert err  # usage or unknown subcommand message


def test_run_install_command_pkexec_uses_scrubbed_env(
    planted_secrets: None,
) -> None:
    captured: dict[str, object] = {}

    def _fake_run(*_a: object, **kwargs: object) -> MagicMock:
        captured["env"] = kwargs.get("env")
        mock = MagicMock()
        mock.returncode = 0
        mock.stdout = ""
        mock.stderr = ""
        return mock

    with patch("oyst_core.privileged.runner.subprocess.run", side_effect=_fake_run):
        result = run_install_command(
            ["pkexec", "/usr/sbin/oyst-helper", "fail2ban", "banned"],
        )
    assert isinstance(result, CommandResult)
    env = captured["env"]
    assert isinstance(env, dict)
    _assert_scrubbed(env)
