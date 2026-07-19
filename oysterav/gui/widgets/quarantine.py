"""Quarantine tab — review and manage isolated threats."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.rpc_actions import request_quarantine_add
from oysterav.gui.widgets.common import (
    clear_list_box,
    format_relative_time,
    make_button,
    make_section_heading,
    run_in_thread,
)


class QuarantinePage:
    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self._window = window
        self._on_status = on_status
        self._entries: list[dict[str, Any]] = []
        self._selected_id: int | None = None
        self._row_ids: dict[Gtk.ListBoxRow, int] = {}

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root.set_margin_start(12)
        root.set_margin_end(12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.refresh_btn = make_button("Refresh")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh())
        self.add_btn = make_button("Add file…")
        self.add_btn.connect("clicked", self._on_add)
        self.restore_btn = make_button("Restore")
        self.restore_btn.set_sensitive(False)
        self.restore_btn.connect("clicked", self._on_restore)
        self.delete_btn = make_button("Delete", destructive=True)
        self.delete_btn.set_sensitive(False)
        self.delete_btn.connect("clicked", self._on_delete)
        self.verify_btn = make_button("Verify vault")
        self.verify_btn.connect("clicked", self._on_verify)
        toolbar.append(self.refresh_btn)
        toolbar.append(self.add_btn)
        toolbar.append(self.restore_btn)
        toolbar.append(self.delete_btn)
        toolbar.append(self.verify_btn)
        toolbar.append(Gtk.Box(hexpand=True))
        root.append(toolbar)

        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.paned.set_hexpand(True)
        self.paned.set_vexpand(True)
        self.paned.set_position(320)

        list_box_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.list_box.connect("row-selected", self._on_row_selected)
        list_box_container.append(self.list_box)
        self.paned.set_start_child(list_box_container)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.detail_box.set_margin_start(16)
        self.detail_box.set_margin_end(16)
        self.detail_box.set_margin_top(8)

        self.empty_page = Adw.StatusPage(
            title="No quarantined items",
            description="Threats quarantined during scans will appear here.",
        )
        self.empty_page.set_icon_name("dialog-password-symbolic")
        self.detail_box.append(self.empty_page)

        self.detail_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.detail_group.set_visible(False)
        self._detail_labels: dict[str, Gtk.Label] = {}
        for key, title in (
            ("path", "Original path"),
            ("threat", "Threat"),
            ("hash", "SHA-256"),
            ("vault", "Vault path"),
            ("time", "Quarantined"),
        ):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            heading = make_section_heading(title)
            value = Gtk.Label(label="—", xalign=0)
            value.set_wrap(True)
            value.set_selectable(True)
            box.append(heading)
            box.append(value)
            self._detail_labels[key] = value
            self.detail_group.append(box)
        self.detail_box.append(self.detail_group)

        detail_scroll.set_child(self.detail_box)
        self.paned.set_end_child(detail_scroll)
        root.append(self.paned)

        self.widget = root

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def refresh(self) -> None:
        run_in_thread(self.client.quarantine_list, self._apply_list, self._apply_error)

    def _apply_list(self, entries: list[dict[str, Any]]) -> bool:
        self._entries = entries
        self._row_ids.clear()
        clear_list_box(self.list_box)
        self._selected_id = None
        self.restore_btn.set_sensitive(False)
        self.delete_btn.set_sensitive(False)

        if not entries:
            self.empty_page.set_visible(True)
            self.detail_group.set_visible(False)
            return False

        self.empty_page.set_visible(False)
        for entry in entries:
            row = Gtk.ListBoxRow()
            entry_id = int(entry.get("id", 0))
            self._row_ids[row] = entry_id
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            box.set_margin_start(12)
            box.set_margin_end(12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            path = entry.get("original_path", "")
            basename = path.rsplit("/", 1)[-1] if path else "?"
            title = Gtk.Label(label=basename, xalign=0)
            title.add_css_class("heading")
            threat = entry.get("threat_name", "")
            when = format_relative_time(entry.get("quarantined_at"))
            subtitle = Gtk.Label(
                label=f"{threat} · {when}",
                xalign=0,
            )
            subtitle.add_css_class("dim-label")
            box.append(title)
            box.append(subtitle)
            row.set_child(box)
            self.list_box.append(row)

        first = self.list_box.get_row_at_index(0)
        if first:
            self.list_box.select_row(first)
        return False

    def _apply_error(self, message: str) -> bool:
        self._set_status(f"Quarantine error: {message}")
        return False

    def _on_row_selected(self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            self._selected_id = None
            self.restore_btn.set_sensitive(False)
            self.delete_btn.set_sensitive(False)
            self.detail_group.set_visible(False)
            return
        entry_id = self._row_ids.get(row) if row is not None else None
        self._selected_id = entry_id
        entry = next((e for e in self._entries if e.get("id") == self._selected_id), None)
        if not entry:
            return
        self.detail_group.set_visible(True)
        self.empty_page.set_visible(False)
        self._detail_labels["path"].set_text(str(entry.get("original_path", "")))
        self._detail_labels["threat"].set_text(str(entry.get("threat_name", "")))
        sha = str(entry.get("sha256", ""))
        self._detail_labels["hash"].set_text(f"{sha[:16]}…{sha[-8:]}" if len(sha) > 24 else sha)
        self._detail_labels["vault"].set_text(str(entry.get("vault_path", "")))
        self._detail_labels["time"].set_text(format_relative_time(entry.get("quarantined_at")))
        self.restore_btn.set_sensitive(True)
        self.delete_btn.set_sensitive(True)

    def _selected_entry(self) -> dict[str, Any] | None:
        if self._selected_id is None:
            return None
        return next((e for e in self._entries if e.get("id") == self._selected_id), None)

    def _confirm(
        self,
        heading: str,
        body: str,
        confirm_label: str,
        on_confirm: Callable[[], None],
    ) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self._window,
            heading=heading,
            body=body,
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("confirm", confirm_label)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        if confirm_label.lower() == "delete":
            dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)
        else:
            dialog.set_response_appearance("confirm", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
            if response == "confirm":
                on_confirm()

        dialog.connect("response", on_response)
        dialog.present()

    def _on_add(self, *_args: object) -> None:
        dialog = Gtk.FileDialog(title="Choose file to quarantine")
        dialog.open(self._window, None, self._on_add_selected)

    def _on_add_selected(self, dialog: Gtk.FileDialog, result: object) -> None:
        from gi.repository import GLib

        try:
            file = dialog.open_finish(result)
        except GLib.Error:
            return
        if file is None:
            return
        path = file.get_path()
        if not path:
            return

        def worker() -> dict[str, Any]:
            return request_quarantine_add(self.client, path)

        def done(_: dict[str, Any]) -> bool:
            if self._on_status:
                self._on_status(f"Quarantined {path}")
            self.refresh()
            return False

        def failed(message: str) -> bool:
            if self._on_status:
                self._on_status(f"Quarantine add failed: {message}")
            return False

        run_in_thread(worker, done, failed)

    def _on_restore(self, *_args: object) -> None:
        entry = self._selected_entry()
        if not entry or self._selected_id is None:
            return
        path = str(entry.get("original_path", ""))

        def do_restore() -> None:
            run_in_thread(
                lambda: self.client.quarantine_restore(self._selected_id),  # type: ignore[arg-type]
                lambda dest: self._after_action(f"Restored to {dest}"),
                lambda msg: self._after_action(f"Restore failed: {msg}", error=True),
            )

        self._confirm(
            "Restore file?",
            f"Restore {path} to its original location?",
            "Restore",
            do_restore,
        )

    def _on_delete(self, *_args: object) -> None:
        entry = self._selected_entry()
        if not entry or self._selected_id is None:
            return
        path = str(entry.get("original_path", ""))
        entry_id = self._selected_id

        def do_delete() -> None:
            run_in_thread(
                lambda: self.client.quarantine_delete(entry_id),
                lambda _: self._after_action("Entry deleted"),
                lambda msg: self._after_action(f"Delete failed: {msg}", error=True),
            )

        self._confirm(
            "Delete quarantined file?",
            f"Permanently delete the quarantined copy of {path}?",
            "Delete",
            do_delete,
        )

    def _on_verify(self, *_args: object) -> None:
        def done(result: dict[str, Any]) -> bool:
            if result.get("ok"):
                self._set_status("Vault integrity OK")
            else:
                bad = result.get("invalid_entries", [])
                self._set_status(f"Vault verify failed: {len(bad)} invalid entries")
            return False

        run_in_thread(self.client.quarantine_verify, done, self._apply_error)

    def _after_action(self, message: str, *, error: bool = False) -> bool:
        self._set_status(message)
        if not error:
            self.refresh()
        return False
