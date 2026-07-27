"""CLI version / GitHub release check."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core import __version__


def test_version_prints_installed() -> None:
    result = CliRunner().invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_check_up_to_date() -> None:
    with patch(
        "oyst_cli.commands.version_cmd.check_app_update",
        return_value={
            "ok": True,
            "current": __version__,
            "latest": __version__,
            "update": None,
            "message": f"oysterAV {__version__} is up to date",
        },
    ):
        result = CliRunner().invoke(cli, ["version", "--check"])
    assert result.exit_code == 0
    assert "up to date" in result.output


def test_version_check_newer_exits_one() -> None:
    with patch(
        "oyst_cli.commands.version_cmd.check_app_update",
        return_value={
            "ok": True,
            "current": "0.1.0",
            "latest": "9.9.9",
            "update": {"kind": "app", "available": "9.9.9"},
            "message": "oysterAV 0.1.0 > 9.9.9 available",
        },
    ):
        result = CliRunner().invoke(cli, ["version", "--check"])
    assert result.exit_code == 1
