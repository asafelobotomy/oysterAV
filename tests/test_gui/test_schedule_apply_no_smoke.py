"""Editing the schedule must not start a scan (the smoke test is a real quick scan)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

gi = pytest.importorskip("gi", reason="PyGObject (gi) not installed", exc_type=ImportError)

try:
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
except ValueError:  # pragma: no cover — typelibs missing
    pytest.skip("GTK4 / libadwaita typelibs not installed", allow_module_level=True)

from oysterav.gui.widgets import settings_schedule_apply  # noqa: E402


def test_settings_auto_apply_skips_smoke_test() -> None:
    page = SimpleNamespace(
        _schedule_apply_timeout=0,
        _loading=False,
        _schedule_applying=False,
        _schedule_run_btn=MagicMock(),
        sched_enabled_row=MagicMock(get_active=MagicMock(return_value=True)),
        client=MagicMock(),
        _window=None,
        _set_status=MagicMock(),
        _apply_error=MagicMock(),
        refresh=MagicMock(),
    )
    with (
        patch.object(settings_schedule_apply, "schedule_validation_error", return_value=""),
        patch.object(settings_schedule_apply, "apply_schedule_timer") as apply,
    ):
        settings_schedule_apply.run_timer_apply(page)  # type: ignore[arg-type]
    assert apply.call_args.kwargs["smoke_test"] is False
