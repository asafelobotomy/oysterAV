"""Clamonacc control helpers for the GTK GUI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import make_button, run_in_thread, show_command_dialog


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

    def failed(message: str) -> bool:
        if on_status:
            on_status(f"Clamonacc: {message}")
        if window:
            show_command_dialog(
                window,
                heading="Could not start clamonacc",
                body=message,
                copy_text="oyst-cli clamonacc enable",
            )
        if on_complete:
            on_complete()
        return False

    run_in_thread(client.clamonacc_enable, done, failed)


def disable_clamonacc_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    if on_status:
        on_status("Stopping clamonacc…")

    def done(result: dict[str, Any]) -> bool:
        if result.get("ok"):
            if on_status:
                on_status("Clamonacc monitoring disabled")
        else:
            if on_status:
                on_status(f"Clamonacc: {result.get('message', 'failed')}")
            if window:
                show_command_dialog(
                    window,
                    heading="Could not stop clamonacc",
                    body=str(result.get("message", "unknown error")),
                    copy_text="oyst-cli clamonacc disable",
                )
        if on_complete:
            on_complete()
        return False

    def failed(message: str) -> bool:
        if on_status:
            on_status(f"Clamonacc: {message}")
        if window:
            show_command_dialog(
                window,
                heading="Could not stop clamonacc",
                body=message,
                copy_text="oyst-cli clamonacc disable",
            )
        if on_complete:
            on_complete()
        return False

    run_in_thread(client.clamonacc_disable, done, failed)


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
        lambda _source, res: _on_folder_selected(
            dialog,
            client,
            res,
            on_status=on_status,
            on_complete=on_complete,
        ),
    )


def _on_folder_selected(
    dialog: Gtk.FileDialog,
    client: OystClient,
    result: object,
    *,
    on_status: Callable[[str], None] | None,
    on_complete: Callable[[], None] | None,
) -> None:
    try:
        folder = dialog.select_folder_finish(result)
    except GLib.Error:
        return
    if folder is None:
        return
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


def populate_clamonacc_paths(
    group: Adw.PreferencesGroup,
    path_rows: list[Adw.ActionRow],
    paths: list[str],
    *,
    on_remove: Callable[[str], None],
) -> None:
    """Replace watched-path rows under a preferences group."""
    for row in path_rows:
        group.remove(row)
    path_rows.clear()
    if not paths:
        empty = Adw.ActionRow(title="No watched paths configured")
        empty.set_subtitle("Add folders for on-access scanning")
        group.add(empty)
        path_rows.append(empty)
        return
    for path in paths:
        action = Adw.ActionRow()
        action.set_title(str(path))
        remove_btn = make_button("Remove", destructive=True, row_suffix=True)
        remove_btn.connect("clicked", lambda _btn, p=str(path): on_remove(p))
        action.add_suffix(remove_btn)
        group.add(action)
        path_rows.append(action)


def _run_ensure(
    worker: Callable[[], dict[str, Any]],
    *,
    window: Gtk.Window | None,
    heading: str,
    copy_text: str,
    on_status: Callable[[str], None] | None,
    on_complete: Callable[[], None] | None,
) -> None:
    if on_status:
        on_status(f"{heading}…")

    def done(result: dict[str, Any]) -> bool:
        ok = bool(result.get("ok"))
        msg = str(result.get("message") or result.get("error") or ("ok" if ok else "failed"))
        if on_status:
            on_status(msg)
        if not ok and window:
            show_command_dialog(window, heading=heading, body=msg, copy_text=copy_text)
        if on_complete:
            on_complete()
        return False

    def failed(message: str) -> bool:
        if on_status:
            on_status(message)
        if window:
            show_command_dialog(window, heading=heading, body=message, copy_text=copy_text)
        if on_complete:
            on_complete()
        return False

    run_in_thread(worker, done, failed)


def ensure_fdpass_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    _run_ensure(
        client.clamonacc_ensure_fdpass,
        window=window,
        heading="Ensure clamonacc --fdpass",
        copy_text="oyst-cli clamonacc ensure-fdpass --confirm",
        on_status=on_status,
        on_complete=on_complete,
    )


def ensure_prevention_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    _run_ensure(
        client.clamonacc_ensure_prevention,
        window=window,
        heading="Ensure host OnAccessPrevention",
        copy_text="oyst-cli clamonacc ensure-prevention --confirm",
        on_status=on_status,
        on_complete=on_complete,
    )


def ensure_virusevent_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    _run_ensure(
        client.virusevent_ensure,
        window=window,
        heading="Ensure VirusEvent bridge",
        copy_text="oyst-cli virusevent ensure --confirm",
        on_status=on_status,
        on_complete=on_complete,
    )


def refresh_onaccess_probe_row(client: OystClient, row: Adw.ActionRow) -> None:
    def done(status: dict[str, Any]) -> bool:
        details = status.get("details") or {}
        onaccess = details.get("onaccess") or {}
        classification = onaccess.get("classification") or "unknown"
        enforced = bool(onaccess.get("prevention_enforced"))
        row.set_subtitle(
            f"{classification}" + (" · blocking" if enforced else " · not blocking"),
        )
        return False

    run_in_thread(client.clamonacc_status, done, lambda _m: False)


def build_host_cocontrol_group(
    client: OystClient,
    *,
    get_window: Callable[[], Gtk.Window | None],
    on_status: Callable[[str], None] | None,
    on_complete: Callable[[], None] | None,
) -> tuple[Adw.PreferencesGroup, Adw.ActionRow]:
    """Build Real-time host co-control group; returns (group, probe_row)."""
    group = Adw.PreferencesGroup(title="Host ClamAV co-control")
    probe = Adw.ActionRow(title="On-access probe")
    probe.set_subtitle("Classification from host clamd.conf")
    group.add(probe)
    actions: list[tuple[str, str, Callable[..., None]]] = [
        ("Ensure --fdpass", "oyst-cli clamonacc ensure-fdpass --confirm", ensure_fdpass_from_gui),
        (
            "Ensure prevention",
            "oyst-cli clamonacc ensure-prevention --confirm",
            ensure_prevention_from_gui,
        ),
        ("Ensure VirusEvent", "oyst-cli virusevent ensure --confirm", ensure_virusevent_from_gui),
    ]
    for title, copy, fn in actions:
        row = Adw.ActionRow(title=title)
        row.set_subtitle(copy)
        btn = make_button("Ensure…", row_suffix=True)
        btn.connect(
            "clicked",
            lambda _b, call=fn: call(
                client,
                window=get_window(),
                on_status=on_status,
                on_complete=on_complete,
            ),
        )
        row.add_suffix(btn)
        group.add(row)
    return group, probe
