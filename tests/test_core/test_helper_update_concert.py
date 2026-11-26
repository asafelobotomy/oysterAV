"""Helper update-concert unit tests."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from oyst_core.privileged.helper_update_concert import run_update_concert
from oyst_core.privileged.oyst_helper import run_helper_argv


def test_update_concert_requires_steps() -> None:
    assert run_update_concert([]) == 2


def test_update_concert_runs_packages_and_rkh() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_update_concert._run_cmd",
            return_value=(0, "ok"),
        ) as run_cmd,
        patch(
            "oyst_core.privileged.helper_update_concert._run_rkhunter",
            return_value=(0, "ok"),
        ) as run_rkh,
        patch(
            "oyst_core.privileged.helper_update_concert.resolve_trusted_argv",
            side_effect=lambda argv: argv,
        ),
    ):
        rc = run_update_concert(
            [
                "--family=arch",
                "--upgrade=rkhunter",
                "--rkh-update",
                "--rkh-propupd",
            ],
        )
    assert rc == 0
    assert run_cmd.call_count == 1
    assert run_rkh.call_count == 2


def test_update_concert_alias_dispatches() -> None:
    with patch(
        "oyst_core.privileged.oyst_helper.run_update_concert_alias",
        return_value=0,
    ) as alias:
        assert run_helper_argv(["update-concert", "--rkh-update"]) == 0
    alias.assert_called_once()


def test_update_concert_unknown_family() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        from oyst_core.privileged.helper_update_concert import _family_upgrade_argv

        _family_upgrade_argv("gentoo", ["clamav"])


def test_update_concert_rejects_non_allowlisted_package() -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        from oyst_core.privileged.helper_update_concert import _family_upgrade_argv

        _family_upgrade_argv("arch", ["nginx"])


def test_update_concert_json_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    with patch(
        "oyst_core.privileged.helper_update_concert._run_rkhunter",
        return_value=(0, "ok"),
    ):
        assert run_update_concert(["--rkh-update"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["steps"][0]["step"] == "rkhunter-update"


def _fake_proc(rc: int, stdout: str = "", stderr: str = "") -> object:
    class _Proc:
        returncode = rc

    proc = _Proc()
    proc.stdout = stdout  # type: ignore[attr-defined]
    proc.stderr = stderr  # type: ignore[attr-defined]
    return proc


_GREP_NOISE = "grep: warning: stray \\ before -\negrep: warning: egrep is obsolescent\n" * 20


@pytest.mark.parametrize(("rc", "ok"), [(0, True), (2, True), (1, False), (127, False)])
def test_rkhunter_update_exit_codes(rc: int, ok: bool, capsys: pytest.CaptureFixture[str]) -> None:
    """rkhunter --update exits 2 after downloading new files: that is success."""
    stdout = "Checking file mirrors.dat [ Updated ]\n"
    with (
        patch(
            "oyst_core.privileged.helper_update_concert.resolve_trusted_argv",
            side_effect=lambda argv: argv,
        ),
        patch(
            "oyst_core.privileged.helper_update_concert.subprocess.run",
            return_value=_fake_proc(rc, stdout, _GREP_NOISE),
        ) as run,
    ):
        assert run_update_concert(["--rkh-update"]) == 0
    assert run.call_args.args[0][:2] == ["rkhunter", "--nocolors"]
    step = json.loads(capsys.readouterr().out.strip())["steps"][0]
    assert step["ok"] is ok
    assert step.get("soft_fail", False) is (not ok)
    assert "stray" not in step["message"]
    assert "egrep" not in step["message"]
    assert "mirrors.dat" in step["message"]


def test_rkhunter_propupd_nonzero_is_soft_fail(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch(
            "oyst_core.privileged.helper_update_concert.resolve_trusted_argv",
            side_effect=lambda argv: argv,
        ),
        patch(
            "oyst_core.privileged.helper_update_concert.subprocess.run",
            return_value=_fake_proc(2, "", "boom"),
        ),
    ):
        assert run_update_concert(["--rkh-propupd"]) == 0
    step = json.loads(capsys.readouterr().out.strip())["steps"][0]
    assert step["ok"] is False
    assert step["soft_fail"] is True
