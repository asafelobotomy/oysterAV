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
    assert run_cmd.call_count == 3


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

        _family_upgrade_argv("gentoo", ["foo"])


def test_update_concert_json_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    with (
        patch(
            "oyst_core.privileged.helper_update_concert._run_cmd",
            return_value=(0, "ok"),
        ),
        patch(
            "oyst_core.privileged.helper_update_concert.resolve_trusted_argv",
            side_effect=lambda argv: argv,
        ),
    ):
        assert run_update_concert(["--rkh-update"]) == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["steps"][0]["step"] == "rkhunter-update"
