"""Medium audit fixes in the GTK GUI: markup, polling, quit guard, setup wizard."""

from __future__ import annotations

import re
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

from gi.repository import Gtk  # noqa: E402

from oysterav.gui import app_quit  # noqa: E402
from oysterav.gui.widgets import plain_rows, scan_job_ui, setup_wizard_actions  # noqa: E402

GUI_ROOT = Path(__file__).resolve().parents[2] / "oysterav" / "gui"
_RAW_ROW = re.compile(
    r"\bAdw\.(ActionRow|ExpanderRow|Banner|SwitchRow|ComboRow|EntryRow|SpinRow|PreferencesRow)\("
)


def _sync_thread(worker: Any, on_success: Any, on_error: Any) -> None:
    try:
        result = worker()
    except Exception as exc:  # noqa: BLE001
        on_error(str(exc))
        return
    on_success(result)


def _labels(widget: Gtk.Widget) -> list[Gtk.Label]:
    out: list[Gtk.Label] = []
    child = widget.get_first_child()
    while child is not None:
        if isinstance(child, Gtk.Label):
            out.append(child)
        out.extend(_labels(child))
        child = child.get_next_sibling()
    return out


def test_no_raw_markup_row_constructors_in_gui() -> None:
    offenders = [
        f"{path.relative_to(GUI_ROOT)}:{n}"
        for path in GUI_ROOT.rglob("*.py")
        if path.name != "plain_rows.py"
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if _RAW_ROW.search(line)
    ]
    assert not offenders, f"use oysterav.gui.widgets.plain_rows helpers: {offenders}"


def test_escape_markup() -> None:
    assert plain_rows.escape_markup("a & <b>") == "a &amp; &lt;b&gt;"


def _require_display() -> None:
    """Skip widget tests on headless runners.

    Gtk.init_check() can return True with no display (e.g. CI); constructing
    libadwaita widgets then segfaults, so require an actual default display.
    """
    from gi.repository import Adw, Gdk

    if not Gtk.init_check() or Gdk.Display.get_default() is None:
        pytest.skip("no display for GTK widgets")
    Adw.init()


def test_plain_rows_display_markup_literally() -> None:
    _require_display()
    text = "/home/u/R&D <b>x</b>"
    rows = [
        plain_rows.action_row(title=text, subtitle=text),
        plain_rows.expander_row(title=text, subtitle=text),
        plain_rows.switch_row(title=text),
        plain_rows.combo_row(title=text),
        plain_rows.entry_row(title=text),
    ]
    for row in rows:
        assert row.get_use_markup() is False
        row.set_title("jail & <i>")
        assert row.get_title() == "jail & <i>"
    action = rows[0]
    action.set_subtitle("rule & <span>")
    shown = {label.get_label() for label in _labels(action)}
    assert "jail & <i>" in shown
    assert all(not label.get_use_markup() for label in _labels(action))
    banner = plain_rows.banner(title=text)
    assert banner.get_use_markup() is False


def _scan_page() -> SimpleNamespace:
    return SimpleNamespace(
        client=MagicMock(),
        progress=MagicMock(),
        _scanning=True,
        _poll_id=0,
        _poll_inflight=False,
        statuses=[],
    )


def test_scan_poll_runs_off_loop_with_inflight_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks: list[Any] = []
    pending: list[tuple[Any, Any, Any]] = []

    def fake_timeout(_ms: int, fn: Any) -> int:
        ticks.append(fn)
        return 7

    monkeypatch.setattr(scan_job_ui.GLib, "timeout_add", fake_timeout)
    monkeypatch.setattr(scan_job_ui, "run_in_thread", lambda w, s, e: pending.append((w, s, e)))
    monkeypatch.setattr(scan_job_ui, "stop_poll", lambda _page: None)
    applied: list[dict[str, Any]] = []
    monkeypatch.setattr(scan_job_ui, "apply_job_status", lambda _p, st: applied.append(st))
    page = _scan_page()
    page._set_status = page.statuses.append

    scan_job_ui.start_poll(page)
    tick = ticks[0]
    assert tick() is True
    assert tick() is True  # still in flight: no second RPC queued
    assert len(pending) == 1

    _worker, on_success, on_error = pending.pop()
    on_error("socket timeout")  # non-RuntimeError failures keep polling and report
    assert page.statuses[-1] == "Scan progress unavailable: socket timeout"
    assert tick() is True
    _worker, on_success, on_error = pending.pop()
    on_success({"active": True, "pack": "clamav"})
    assert applied == [{"active": True, "pack": "clamav"}]
    page._scanning = False
    assert tick() is False


def test_quit_guard_asks_only_when_job_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_quit, "run_in_thread", _sync_thread)
    prompts: list[str] = []
    monkeypatch.setattr(
        app_quit, "present_quit_dialog", lambda _w, detail, _q: prompts.append(detail)
    )
    quits: list[bool] = []
    client = MagicMock()

    client.job_status.return_value = {"active": False}
    app_quit.confirm_quit_if_busy(None, client, lambda: quits.append(True))
    assert quits == [True] and prompts == []

    client.job_status.return_value = {"active": True, "pack": "maldet", "message": "Scanning…"}
    app_quit.confirm_quit_if_busy(None, client, lambda: quits.append(True))
    assert quits == [True]
    assert prompts == ["maldet — Scanning…"]

    client.job_status.side_effect = RuntimeError("rpc down")
    app_quit.confirm_quit_if_busy(None, client, lambda: quits.append(True))
    assert quits == [True, True]


def test_rerun_wizard_does_not_reset_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    from oysterav.gui import app

    created: list[Any] = []

    def fake_wizard(*_a: Any, **kwargs: Any) -> MagicMock:
        created.append(kwargs)
        return MagicMock()

    monkeypatch.setattr(app, "SetupWizard", fake_wizard)
    fake = SimpleNamespace(
        client=MagicMock(),
        _refresh_shell=lambda: None,
        _navigate=lambda *_a, **_k: None,
        _set_status=lambda _t: None,
    )
    app.OysterWindow.present_setup_wizard(fake)  # type: ignore[arg-type]
    fake.client.setup_reset.assert_not_called()
    assert len(created) == 1


def _wizard() -> SimpleNamespace:
    return SimpleNamespace(
        client=MagicMock(),
        dialog=MagicMock(),
        auto_quarantine=MagicMock(get_active=lambda: True),
        _dismissed=False,
        _finish_pending=False,
        _on_complete=MagicMock(),
        _on_changed=None,
        _update_nav=lambda: None,
        _set_status=lambda _t: None,
    )


def test_wizard_cancel_leaves_state_and_finish_runs_off_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wizard = _wizard()
    setup_wizard_actions.complete_finish(wizard, mark_complete=False)  # type: ignore[arg-type]
    wizard.client.setup_run.assert_not_called()
    wizard.client.setup_reset.assert_not_called()
    wizard.dialog.destroy.assert_called_once()

    pending: list[tuple[Any, Any, Any]] = []
    monkeypatch.setattr(
        setup_wizard_actions,
        "run_in_thread",
        lambda w, s, e: pending.append((w, s, e)),
    )
    wizard = _wizard()
    setup_wizard_actions.complete_finish(wizard, mark_complete=True)  # type: ignore[arg-type]
    assert wizard._finish_pending is True
    wizard.client.setup_run.assert_not_called()  # queued, not run on the GTK loop
    worker, on_success, _on_error = pending.pop()
    worker()
    assert wizard.client.setup_run.call_args.kwargs["mark_complete"] is True
    on_success({})
    wizard.dialog.destroy.assert_called_once()
    wizard._on_complete.assert_called_once()
