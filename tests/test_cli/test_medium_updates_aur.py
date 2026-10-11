"""AUR upgrades in update-all are opt-in (audit M: --noconfirm AUR upgrades)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.rpc_handlers.system import handle_updates_apply


@pytest.mark.parametrize(("flags", "expected"), [([], False), (["--confirm-aur"], True)])
def test_updates_apply_cli_threads_confirm_aur(flags: list[str], expected: bool) -> None:
    with patch(
        "oyst_cli.commands.updates_cmd.apply_all_updates",
        return_value={"ok": True, "steps": []},
    ) as apply:
        result = CliRunner().invoke(cli, ["updates", "apply", "--confirm", *flags, "--json"])
    assert result.exit_code == 0, result.output
    apply.assert_called_once_with(confirm_aur=expected)


@pytest.mark.parametrize(
    ("params", "expected"),
    [({}, False), ({"confirm_aur": True}, True), ({"confirm_aur": "yes"}, False)],
)
def test_updates_apply_rpc_requires_literal_true(params: dict[str, object], expected: bool) -> None:
    with patch("oyst_core.updates.apply_all_updates", return_value={"ok": True}) as apply:
        handle_updates_apply(params, None)  # type: ignore[arg-type]
    apply.assert_called_once_with(confirm_aur=expected)
