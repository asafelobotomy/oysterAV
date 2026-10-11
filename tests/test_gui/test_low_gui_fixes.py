"""Low-severity audit fixes in the GTK GUI: confirms, races, link safety, copy hints."""

from __future__ import annotations

from pathlib import Path
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

from oysterav.gui.widgets import (  # noqa: E402
    confirm_dialog,
    quarantine,
    settings,
    settings_terminal_ui,
    setup_wizard_actions,
    status_bar,
)

GUI_ROOT = Path(__file__).resolve().parents[2] / "oysterav" / "gui"


class _FakeDialog:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.responses: list[str] = []
        self.handler: Any = None
        self.presented_on: Any = "unset"

    def add_response(self, rid: str, _label: str) -> None:
        self.responses.append(rid)

    def set_response_appearance(self, *_a: Any) -> None: ...
    def set_default_response(self, rid: str) -> None:
        self.default = rid

    def set_close_response(self, rid: str) -> None:
        self.close = rid

    def connect(self, _sig: str, handler: Any) -> None:
        self.handler = handler

    def present(self, parent: Any = None) -> None:
        self.presented_on = parent


def test_clamonacc_remove_asks_before_removing(monkeypatch: pytest.MonkeyPatch) -> None:
    dialogs: list[_FakeDialog] = []

    def factory(**kw: Any) -> _FakeDialog:
        dialogs.append(_FakeDialog(**kw))
        return dialogs[-1]

    monkeypatch.setattr(confirm_dialog.Adw, "AlertDialog", factory, raising=False)
    removed: list[str] = []
    monkeypatch.setattr(
        settings, "remove_clamonacc_path_from_gui", lambda _c, p, **_k: removed.append(p)
    )
    page = SimpleNamespace(
        _window=None, client=MagicMock(), _set_status=lambda _m: None, refresh=lambda: None
    )
    settings.SettingsPage._on_remove_clamonacc_path(page, "/srv/data")  # type: ignore[arg-type]
    assert removed == []
    dlg = dialogs[0]
    assert dlg.default == "cancel" and dlg.close == "cancel"
    assert "/srv/data" in dlg.kwargs["body"]
    dlg.handler(dlg, "cancel")
    assert removed == []
    dlg.handler(dlg, "confirm")
    assert removed == ["/srv/data"]


def test_quarantine_restore_captures_id_before_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    pending: list[Any] = []
    monkeypatch.setattr(quarantine, "run_in_thread", lambda w, s, e: pending.append(w))
    client = MagicMock()
    page = SimpleNamespace(
        client=client,
        _selected_id=42,
        _selected_entry=lambda: {"original_path": "/tmp/x"},
        _confirm=lambda _h, _b, _l, cb: cb(),
        _after_action=lambda *_a, **_k: None,
    )
    quarantine.QuarantinePage._on_restore(page)  # type: ignore[arg-type]
    page._selected_id = None  # selection changes before the worker runs
    pending[0]()
    client.quarantine_restore.assert_called_once_with(42)


def _terminal_page() -> SimpleNamespace:
    return SimpleNamespace(
        client=MagicMock(),
        terminal_show_raw_row=SimpleNamespace(get_active=lambda: False),
        _terminal_since_id=0,
        _terminal_entries=[],
        _terminal_inflight=False,
        _terminal_gen=0,
    )


def test_terminal_poll_inflight_guard_and_dedupe(monkeypatch: pytest.MonkeyPatch) -> None:
    pending: list[tuple[Any, Any, Any]] = []
    monkeypatch.setattr(
        settings_terminal_ui, "run_in_thread", lambda w, s, e: pending.append((w, s, e))
    )
    appended: list[list[dict[str, Any]]] = []
    monkeypatch.setattr(settings_terminal_ui, "append_entries", lambda _p, e: appended.append(e))
    monkeypatch.setattr(settings_terminal_ui, "render_transcript", lambda _p: None)
    page = _terminal_page()

    settings_terminal_ui.refresh_terminal(page, incremental=False)  # type: ignore[arg-type]
    settings_terminal_ui.refresh_terminal(page, incremental=True)  # type: ignore[arg-type]
    assert len(pending) == 1  # incremental skipped while full reload in flight
    pending.pop()[1]([{"id": 3}, {"id": 5}])
    assert page._terminal_since_id == 5

    settings_terminal_ui.refresh_terminal(page, incremental=True)  # type: ignore[arg-type]
    assert len(pending) == 1
    pending.pop()[1]([{"id": 5}, {"id": 6}])  # overlapping row 5 must not duplicate
    assert [e["id"] for e in page._terminal_entries] == [3, 5, 6]
    assert appended == [[{"id": 6}]]
    assert page._terminal_since_id == 6 and page._terminal_inflight is False


def test_terminal_stale_incremental_ignored_after_full_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pending: list[tuple[Any, Any, Any]] = []
    monkeypatch.setattr(
        settings_terminal_ui, "run_in_thread", lambda w, s, e: pending.append((w, s, e))
    )
    monkeypatch.setattr(settings_terminal_ui, "append_entries", lambda *_a: None)
    monkeypatch.setattr(settings_terminal_ui, "render_transcript", lambda _p: None)
    page = _terminal_page()
    settings_terminal_ui.refresh_terminal(page, incremental=True)  # type: ignore[arg-type]
    settings_terminal_ui.refresh_terminal(page, incremental=False)  # type: ignore[arg-type]
    stale, full = pending
    full[1]([{"id": 9}])
    stale[1]([{"id": 1}, {"id": 2}])
    assert [e["id"] for e in page._terminal_entries] == [9]


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        ("https://security.example/adv/1", "https://security.example/adv/1"),
        ("http://security.example/adv/1", None),
        ("file:///etc/passwd", None),
        ("javascript:alert(1)", None),
        ("https:///nohost", None),
        ("https://ok.example/\nx", None),
        ("", None),
        (None, None),
    ],
)
def test_safe_news_uri(link: object, expected: str | None) -> None:
    assert status_bar.safe_news_uri(link) == expected


def test_news_click_ignores_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    launched: list[str] = []
    monkeypatch.setattr(
        status_bar.Gio.AppInfo, "launch_default_for_uri", lambda uri, _c: launched.append(uri)
    )
    bar = SimpleNamespace(_news_items=[{"link": "file:///etc/shadow"}])
    status_bar.StatusBar._on_news_clicked(bar)  # type: ignore[arg-type]
    assert launched == []
    bar._news_items = [{"link": "https://lwn.net/x"}]
    status_bar.StatusBar._on_news_clicked(bar)  # type: ignore[arg-type]
    assert launched == ["https://lwn.net/x"]


def test_copy_hints_do_not_run_extra_privileged_steps() -> None:
    hint = setup_wizard_actions.FINISH_RETRY_HINT
    for flag in ("--skip-packs", "--skip-schedule", "--skip-bootstrap", "--skip-harden"):
        assert flag in hint
    assert "--no-enable-firewall" in hint
    app_src = (GUI_ROOT / "app.py").read_text(encoding="utf-8")
    assert 'copy_text="oyst-cli setup run"' not in app_src
    assert 'copy_text="oyst-cli setup check --json"' in app_src
