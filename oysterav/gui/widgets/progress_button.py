"""In-button install/remove progress helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import GLib, Gtk  # noqa: E402

from oysterav.gui.widgets.common import run_in_thread


def format_progress_label(verb: str, percent: int) -> str:
    return f"{verb}… {max(0, min(100, int(percent)))}%"


def run_progress_button(
    button: Gtk.Button,
    worker: Callable[[Callable[[int], None]], Any],
    *,
    busy_verb: str = "Installing",
    idle_label: str | None = None,
    on_success: Callable[[Any], None] | None = None,
    on_error: Callable[[str], None] | None = None,
) -> None:
    """Disable button, show percent on the label, run worker with report(percent)."""
    restore = idle_label if idle_label is not None else (button.get_label() or busy_verb)
    button.set_sensitive(False)
    button.set_label(format_progress_label(busy_verb, 0))

    def report(percent: int) -> None:
        GLib.idle_add(button.set_label, format_progress_label(busy_verb, percent))

    def done(result: Any) -> bool:
        button.set_sensitive(True)
        button.set_label(restore)
        if on_success:
            on_success(result)
        return False

    def fail(message: str) -> bool:
        button.set_sensitive(True)
        button.set_label(restore)
        if on_error:
            on_error(message)
        return False

    run_in_thread(lambda: worker(report), done, fail)
