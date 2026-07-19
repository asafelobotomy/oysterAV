"""Clamonacc control helpers for the GTK GUI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog


def enable_clamonacc_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    if on_status:
        on_status("Starting clamonacc…")

    def done(result: dict[str, Any]) -> bool:
        if on_status:
            if result.get("ok"):
                on_status("Clamonacc monitoring enabled")
            else:
                on_status(f"Clamonacc: {result.get('message', 'failed')}")
        if not result.get("ok") and window:
            show_command_dialog(
                window,
                heading="Could not start clamonacc",
                body=str(result.get("message", "unknown error")),
                copy_text="oyst-cli clamonacc enable",
            )
        if on_complete:
            on_complete()
        return False

    run_in_thread(
        client.clamonacc_enable,
        done,
        lambda m: on_status(f"Clamonacc: {m}") if on_status else False,
    )


def disable_clamonacc_from_gui(
    client: OystClient,
    *,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    def done(_result: dict[str, Any]) -> bool:
        if on_status:
            on_status("Clamonacc monitoring disabled")
        if on_complete:
            on_complete()
        return False

    run_in_thread(
        client.clamonacc_disable,
        done,
        lambda m: on_status(f"Clamonacc: {m}") if on_status else False,
    )


def refresh_clamonacc_subtitle(client: OystClient, row: Adw.ActionRow) -> None:
    def done(status: dict[str, Any]) -> bool:
        details = status.get("details") or {}
        running = bool(details.get("running"))
        clamd = bool(details.get("clamd_running"))
        parts = []
        if running:
            parts.append("Running")
        else:
            parts.append("Stopped")
        if not clamd:
            parts.append("clamd down")
        row.set_subtitle(" · ".join(parts))
        return False

    run_in_thread(client.clamonacc_status, done, lambda _m: False)


def add_clamonacc_path_from_dialog(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    if window is None:
        return
    dialog = Gtk.FileDialog(title="Choose folder to watch")
    dialog.select_folder(
        window,
        None,
        None,
        lambda _source, res, _data: _on_folder_selected(
            client,
            res,
            on_status=on_status,
            on_complete=on_complete,
        ),
    )


def _on_folder_selected(
    client: OystClient,
    result: object,
    *,
    on_status: Callable[[str], None] | None,
    on_complete: Callable[[], None] | None,
) -> None:
    try:
        folder = Gtk.FileDialog.select_folder_finish(result)
        path = folder.get_path()
        if path is None:
            return
        path_str = str(path)

        def worker() -> str:
            client.clamonacc_add_path(path_str)
            return path_str

        def done(added: str) -> bool:
            if on_status:
                on_status(f"Added watch path: {added}")
            if on_complete:
                on_complete()
            return False

        run_in_thread(worker, done, lambda m: on_status(f"Path error: {m}") if on_status else False)
    except GLib.Error:
        return


def remove_clamonacc_path_from_gui(
    client: OystClient,
    path: str,
    *,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    def worker() -> str:
        client.clamonacc_remove_path(path)
        return path

    def done(removed: str) -> bool:
        if on_status:
            on_status(f"Removed watch path: {removed}")
        if on_complete:
            on_complete()
        return False

    run_in_thread(worker, done, lambda m: on_status(f"Path error: {m}") if on_status else False)
