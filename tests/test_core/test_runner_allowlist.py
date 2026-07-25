"""Tests for install command allowlist basename resolution."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged.runner import (
    _argv_needs_user_session,
    _command_basename,
    command_scrubbed_env,
    run_command,
    run_install_command,
    scrubbed_env_for_argv,
    user_session_scrubbed_env,
)


def test_command_basename_resolves_full_paru_path() -> None:
    assert _command_basename(["/usr/bin/paru", "-S", "chkrootkit"]) == "paru"


def test_command_basename_pkexec_paru() -> None:
    assert _command_basename(["pkexec", "/usr/bin/paru", "-S", "maldet"]) == "paru"


def test_install_command_rejects_unknown_binary_path() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        run_install_command(["/tmp/oyst-maldet/extract/maldetect-1.6.6/install.sh"])


def test_run_command_scrubs_secret_env() -> None:
    captured: dict[str, str] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs.get("env") or {})

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    with (
        patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "s3cr3t", "LANG": "C"}, clear=False),
        patch("oyst_core.privileged.runner.subprocess.run", side_effect=fake_run),
    ):
        run_command(["pgrep", "-x", "clamd"])
    assert "AWS_SECRET_ACCESS_KEY" not in captured
    assert captured.get("PATH")
    assert captured.get("LANG") == "C"
    assert "DBUS_SESSION_BUS_ADDRESS" not in captured


def test_argv_needs_user_session() -> None:
    assert _argv_needs_user_session(["systemctl", "--user", "daemon-reload"])
    assert _argv_needs_user_session(
        ["flatpak-spawn", "--host", "systemctl", "--user", "enable", "--now", "u.timer"],
    )
    assert not _argv_needs_user_session(["systemctl", "is-active", "clamd"])
    assert not _argv_needs_user_session(["pgrep", "-x", "clamd"])


def test_user_session_env_keeps_bus_and_scrubs_secrets(tmp_path: Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    bus = runtime / "bus"
    bus.write_text("", encoding="utf-8")
    with patch.dict(
        os.environ,
        {
            "AWS_SECRET_ACCESS_KEY": "s3cr3t",
            "LANG": "C",
            "XDG_RUNTIME_DIR": str(runtime),
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
            "USER": "tester",
            "HOME": str(tmp_path),
        },
        clear=False,
    ):
        env = user_session_scrubbed_env()
        session_argv_env = scrubbed_env_for_argv(["systemctl", "--user", "daemon-reload"])
        plain_env = command_scrubbed_env()
    assert env["DBUS_SESSION_BUS_ADDRESS"].endswith("/bus")
    assert env["XDG_RUNTIME_DIR"] == str(runtime)
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "DBUS_SESSION_BUS_ADDRESS" in session_argv_env
    assert "DBUS_SESSION_BUS_ADDRESS" not in plain_env


def test_user_session_env_synthesizes_bus_from_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.privileged.runner.os.getuid", lambda: 4242)
    with (
        patch.dict(os.environ, {"LANG": "C"}, clear=True),
        patch(
            "oyst_core.privileged.runner.os.path.isdir",
            side_effect=lambda path: path == "/run/user/4242",
        ),
        patch(
            "oyst_core.privileged.runner.os.path.exists",
            side_effect=lambda path: path == "/run/user/4242/bus",
        ),
    ):
        env = user_session_scrubbed_env()
    assert env.get("XDG_RUNTIME_DIR") == "/run/user/4242"
    assert env.get("DBUS_SESSION_BUS_ADDRESS") == "unix:path=/run/user/4242/bus"


def test_run_command_systemctl_user_passes_session_env() -> None:
    captured: dict[str, str] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs.get("env") or {})

        class Proc:
            returncode = 0
            stdout = "active"
            stderr = ""

        return Proc()

    with (
        patch.dict(
            os.environ,
            {
                "AWS_SECRET_ACCESS_KEY": "s3cr3t",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "LANG": "C",
            },
            clear=False,
        ),
        patch("oyst_core.privileged.runner.subprocess.run", side_effect=fake_run),
    ):
        run_command(["systemctl", "--user", "is-active", "oyst-scan.timer"])
    assert captured.get("DBUS_SESSION_BUS_ADDRESS") == "unix:path=/run/user/1000/bus"
    assert captured.get("XDG_RUNTIME_DIR") == "/run/user/1000"
    assert "AWS_SECRET_ACCESS_KEY" not in captured
