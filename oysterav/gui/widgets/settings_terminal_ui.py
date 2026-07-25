"""Settings Terminal section — persistent session transcript viewer."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gio", "2.0")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from oyst_core.config import data_dir
from oyst_core.terminal_log import format_entry_txt
from oysterav.gui.rpc_actions import (
    request_terminal_clear,
    request_terminal_export,
    request_terminal_list,
)
from oysterav.gui.widgets.common import make_button, run_in_thread

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage

POLL_MS = 1500


def build_terminal_section(page: SettingsPage) -> None:
    root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    root.set_margin_top(12)
    root.set_margin_bottom(12)
    root.set_margin_start(12)
    root.set_margin_end(12)

    prefs = Adw.PreferencesGroup(
        title="Terminal",
        description="Verbose backend log for oysterAV and oyst-cli actions.",
    )
    page.terminal_show_raw_row = Adw.SwitchRow(title="Show raw output")
    page.terminal_show_raw_row.set_subtitle(
        "Advanced: include full stdout/stderr and RPC payloads (redacted).",
    )
    page.terminal_show_raw_row.connect(
        "notify::active",
        lambda *a: on_show_raw_saved(page, *a),
    )
    prefs.add(page.terminal_show_raw_row)

    actions = Adw.ActionRow(title="Log actions")
    clear_btn = make_button("Clear log", row_suffix=True)
    clear_btn.connect("clicked", lambda *_: on_clear_log(page))
    export_btn = make_button("Export…", row_suffix=True)
    export_btn.connect("clicked", lambda *_: on_export(page))
    actions.add_suffix(clear_btn)
    actions.add_suffix(export_btn)
    prefs.add(actions)
    root.append(prefs)

    scrolled = Gtk.ScrolledWindow()
    scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scrolled.set_vexpand(True)
    scrolled.set_hexpand(True)
    scrolled.set_min_content_height(280)
    page.terminal_view = Gtk.TextView(
        editable=False,
        cursor_visible=False,
        monospace=True,
        wrap_mode=Gtk.WrapMode.WORD_CHAR,
    )
    page.terminal_view.add_css_class("terminal-log")
    page.terminal_buffer = page.terminal_view.get_buffer()
    scrolled.set_child(page.terminal_view)
    root.append(scrolled)

    page._terminal_since_id = 0
    page._terminal_poll_id = 0
    page._terminal_entries = []
    page._section_pages["terminal"] = root
    # Own scrolling via TextView host — avoid nested ScrolledWindows.
    page._stack.add_named(root, "terminal")


def on_show_raw_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    if getattr(page, "_loading", False):
        return
    page._save("ui.terminal_show_raw", "true" if row.get_active() else "false")
    page._terminal_since_id = 0
    refresh_terminal(page, incremental=False)


def apply_terminal_config(page: SettingsPage, ui: dict[str, Any]) -> None:
    page._loading = True
    try:
        page.terminal_show_raw_row.set_active(bool(ui.get("terminal_show_raw", False)))
    finally:
        page._loading = False


def start_terminal_poll(page: SettingsPage) -> None:
    stop_terminal_poll(page)

    def tick() -> bool:
        if page._stack.get_visible_child_name() != "terminal":
            page._terminal_poll_id = 0
            return False
        refresh_terminal(page, incremental=True)
        return True

    page._terminal_poll_id = GLib.timeout_add(POLL_MS, tick)
    refresh_terminal(page, incremental=False)


def stop_terminal_poll(page: SettingsPage) -> None:
    pid = getattr(page, "_terminal_poll_id", 0) or 0
    if pid:
        GLib.source_remove(pid)
        page._terminal_poll_id = 0


def refresh_terminal(page: SettingsPage, *, incremental: bool) -> None:
    show_raw = bool(page.terminal_show_raw_row.get_active())
    since = int(getattr(page, "_terminal_since_id", 0) or 0) if incremental else 0

    def worker() -> list[dict[str, Any]]:
        return request_terminal_list(
            page.client,
            limit=2000 if not incremental else 500,
            since_id=since,
            all_layers=show_raw,
            layers=None if show_raw else ["structured"],
        )

    def done(entries: list[dict[str, Any]]) -> bool:
        if not incremental:
            page._terminal_entries = list(entries)
            page._terminal_since_id = int(entries[-1]["id"]) if entries else 0
            render_transcript(page)
            return False
        if entries:
            page._terminal_entries.extend(entries)
            page._terminal_since_id = int(entries[-1]["id"])
            append_entries(page, entries)
        return False

    def failed(_message: str) -> bool:
        return False

    run_in_thread(worker, done, failed)


def render_transcript(page: SettingsPage) -> None:
    show_raw = bool(page.terminal_show_raw_row.get_active())
    lines: list[str] = []
    for entry in getattr(page, "_terminal_entries", []):
        layer = str(entry.get("layer") or "")
        if not show_raw and layer == "raw":
            continue
        text = format_entry_txt(entry)
        if layer == "raw":
            text = f"[raw] {text}"
        lines.append(text)
    page.terminal_buffer.set_text("\n".join(lines))
    end = page.terminal_buffer.get_end_iter()
    page.terminal_view.scroll_to_iter(end, 0.0, False, 0.0, 1.0)


def append_entries(page: SettingsPage, entries: list[dict[str, Any]]) -> None:
    show_raw = bool(page.terminal_show_raw_row.get_active())
    if not entries:
        return
    buf = page.terminal_buffer
    end = buf.get_end_iter()
    chunks: list[str] = []
    for entry in entries:
        layer = str(entry.get("layer") or "")
        if not show_raw and layer == "raw":
            continue
        text = format_entry_txt(entry)
        if layer == "raw":
            text = f"[raw] {text}"
        chunks.append(text)
    if not chunks:
        return
    prefix = "\n" if buf.get_char_count() > 0 else ""
    buf.insert(end, prefix + "\n".join(chunks))
    end = buf.get_end_iter()
    page.terminal_view.scroll_to_iter(end, 0.0, False, 0.0, 1.0)


def on_clear_log(page: SettingsPage) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Clear terminal log?",
        body="This permanently deletes the session transcript. This cannot be undone.",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Clear log")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def done(_result: dict[str, Any]) -> bool:
            page._terminal_entries = []
            page._terminal_since_id = 0
            page.terminal_buffer.set_text("")
            page._set_status("Terminal log cleared")
            return False

        def on_err(message: str) -> bool:
            page._set_status(f"Clear failed: {message}")
            return False

        run_in_thread(lambda: request_terminal_clear(page.client), done, on_err)

    dialog.connect("response", on_response)
    dialog.present()


def on_export(page: SettingsPage) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Export terminal log",
        body="Choose plain text (.txt) or JSON Lines (.jsonl).",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("txt", "Text")
    dialog.add_response("jsonl", "JSONL")
    dialog.set_default_response("txt")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("txt", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response in {"txt", "jsonl"}:
            save_export_dialog(page, fmt=response)

    dialog.connect("response", on_response)
    dialog.present()


def save_export_dialog(page: SettingsPage, *, fmt: str) -> None:
    exports = data_dir() / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    file_dialog = Gtk.FileDialog(title="Save terminal export")
    file_dialog.set_initial_name(f"oysterav-terminal.{fmt}")
    file_dialog.set_initial_folder(Gio.File.new_for_path(str(exports)))

    def on_saved(_dlg: Gtk.FileDialog, result: object) -> None:
        try:
            gfile = file_dialog.save_finish(result)
        except GLib.Error:
            return
        if gfile is None:
            return
        path = gfile.get_path()
        if not path:
            return

        def worker() -> dict[str, Any]:
            return request_terminal_export(page.client, path, fmt=fmt)

        def done(result: dict[str, Any]) -> bool:
            if not result.get("ok"):
                page._set_status(f"Export failed: {result.get('error')}")
                return False
            page._set_status(f"Exported to {result.get('path')}")
            return False

        def on_err(message: str) -> bool:
            page._set_status(f"Export failed: {message}")
            return False

        run_in_thread(worker, done, on_err)

    file_dialog.save(page._window, None, on_saved)
