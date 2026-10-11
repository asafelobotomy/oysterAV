"""Quit guard: the RPC server (and any running job) lives in the GUI process."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.widgets.common import run_in_thread


def job_is_active(status: object) -> bool:
    return isinstance(status, dict) and bool(status.get("active"))


def describe_job(status: dict[str, Any]) -> str:
    kind = str(status.get("pack") or "").strip()
    message = str(status.get("message") or "").strip()
    bits = [b for b in (kind, message) if b]
    return " — ".join(bits) if bits else "A scan or maintenance job is running."


def confirm_quit_if_busy(
    window: Gtk.Window | None,
    client: Any,
    on_quit: Callable[[], None],
) -> None:
    """Quit now when idle; otherwise ask first (quitting cancels the running job).

    ``job.status`` is an RPC, so it runs off the GTK loop. If the status cannot
    be read the app quits, matching the previous behaviour.
    """

    def on_status(status: object) -> bool:
        if job_is_active(status) and isinstance(status, dict):
            present_quit_dialog(window, describe_job(status), on_quit)
        else:
            on_quit()
        return False

    def on_error(_message: str) -> bool:
        on_quit()
        return False

    run_in_thread(client.job_status, on_status, on_error)


def present_quit_dialog(
    window: Gtk.Window | None,
    detail: str,
    on_quit: Callable[[], None],
) -> None:
    if window is not None and not window.get_visible():
        window.set_visible(True)  # Quit from the tray while hidden: show the prompt
        window.present()
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Quit while a job is running?",
        body=(
            "The job runs in the oysterAV backend (oyst-cli serve), not in this "
            "window, so it keeps running after you quit. Its results appear in "
            "Reports the next time you open oysterAV; you can also follow it with "
            f"`oyst-cli job status`.\n\n{detail}"
        ),
    )
    dialog.add_response("cancel", "Stay open")
    dialog.add_response("quit", "Quit")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "quit":
            on_quit()

    dialog.connect("response", on_response)
    dialog.present()


def present_startup_error(app: Adw.Application, message: str) -> None:
    """Show why the backend could not start instead of crashing in do_activate."""
    dialog = Adw.MessageDialog(
        heading="oysterAV could not start its backend",
        body=(
            f"{message}\n\nAnother process may be holding the oysterAV socket. "
            "Close other oysterAV windows (or a running `oyst-cli serve`) and try again."
        ),
    )
    dialog.set_application(app)
    dialog.add_response("close", "Close")
    dialog.set_default_response("close")
    dialog.set_close_response("close")
    dialog.connect("response", lambda *_a: app.quit())
    dialog.present()
