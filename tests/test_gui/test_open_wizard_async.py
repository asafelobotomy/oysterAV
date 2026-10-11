"""Remaining open item: wizard config reads must not block the GTK main loop."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

gi = pytest.importorskip("gi", reason="PyGObject (gi) not installed", exc_type=ImportError)

try:
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
except ValueError:  # pragma: no cover — typelibs missing
    pytest.skip("GTK4 / libadwaita typelibs not installed", allow_module_level=True)

from oysterav.gui.widgets import setup_wizard, setup_wizard_firewall  # noqa: E402
from oysterav.gui.widgets.setup_wizard import SetupWizard  # noqa: E402


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ({"runtime": {"mode": "lite"}}, False),
        ({"runtime": {"mode": "full"}}, True),
        ({}, True),
        (None, True),
    ],
)
def test_full_mode_from_config(config: object, expected: bool) -> None:
    assert SetupWizard._full_mode_from_config(config) is expected


def test_load_preferences_runs_rpc_in_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    deferred: list[tuple[Any, Any, Any]] = []
    monkeypatch.setattr(setup_wizard, "run_in_thread", lambda *a: deferred.append(a))
    client = MagicMock()
    client.config_get.return_value = {"runtime": {"mode": "lite"}, "quarantine": {"auto": True}}
    toggle = MagicMock()
    wiz = SimpleNamespace(
        client=client,
        _full_mode=True,
        auto_quarantine=toggle,
        _refresh_ready_summary=MagicMock(),
        _set_status=MagicMock(),
        _full_mode_from_config=SetupWizard._full_mode_from_config,
    )
    SetupWizard._load_preferences(wiz)  # type: ignore[arg-type]
    client.config_get.assert_not_called()  # nothing ran on the calling (main) thread
    ((worker, done, _fail),) = deferred
    done(worker())
    assert wiz._full_mode is False
    toggle.set_active.assert_called_once_with(True)


def test_firewall_saved_backend_read_in_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    deferred: list[tuple[Any, Any, Any]] = []
    monkeypatch.setattr(setup_wizard_firewall, "run_in_thread", lambda *a: deferred.append(a))
    client = MagicMock()
    client.firewall_recommend.return_value = {"recommended": "ufw", "detect": {}}
    client.config_get.return_value = "firewalld"
    wiz = MagicMock()
    wiz.client = client
    setup_wizard_firewall.refresh_firewall_page(wiz)
    client.config_get.assert_not_called()
    ((worker, done, _fail),) = deferred
    done(worker())
    wiz.firewall_backend_row.set_selected.assert_called_once_with(1)
