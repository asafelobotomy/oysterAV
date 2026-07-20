"""Settings tab — user preferences."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets import (
    settings_general_ui,
    settings_host_audit_ui,
    settings_maintenance_ui,
    settings_schedule_ui,
)
from oysterav.gui.widgets.clamonacc_ui import (
    add_clamonacc_path_from_dialog,
    disable_clamonacc_from_gui,
    enable_clamonacc_from_gui,
    populate_clamonacc_paths,
    refresh_clamonacc_subtitle,
    remove_clamonacc_path_from_gui,
)
from oysterav.gui.widgets.common import (
    make_button,
    make_scrolled_page,
    run_in_thread,
    show_command_dialog,
)
from oysterav.gui.widgets.packs import PackListWidget
from oysterav.gui.widgets.services_ui import build_services_group
from oysterav.gui.widgets.settings_const import SETTINGS_SECTION_IDS, SETTINGS_SECTIONS
from oysterav.gui.widgets.settings_general_ui import apply_settings_data

__all__ = ["SETTINGS_SECTIONS", "SettingsPage"]


class SettingsPage:
    # Attached by settings_*_ui builders / realtime section.
    backend_status_row: Adw.ActionRow
    security_news_row: Adw.SwitchRow
    _news_source_rows: dict[str, Adw.SwitchRow]
    auto_quarantine_row: Adw.SwitchRow
    profile_row: Adw.ComboRow
    backend_row: Adw.ComboRow
    theme_row: Adw.ComboRow
    run_at_startup_row: Adw.SwitchRow
    start_minimized_row: Adw.SwitchRow
    minimize_to_tray_row: Adw.SwitchRow
    schedule_status_row: Adw.ActionRow
    sched_enabled_row: Adw.SwitchRow
    sched_profile_row: Adw.ComboRow
    sched_frequency_row: Adw.ComboRow
    sched_time_row: Adw.EntryRow
    sched_weekday_row: Adw.ComboRow
    sched_calendar_row: Adw.EntryRow
    sched_packs_row: Adw.EntryRow
    sched_paths_row: Adw.EntryRow
    sched_quarantine_row: Adw.ComboRow
    sched_backend_row: Adw.ComboRow
    sched_persistent_row: Adw.SwitchRow
    _schedule_run_btn: Gtk.Button
    firewall_row: Adw.ActionRow
    audit_status_row: Adw.ActionRow
    _audit_detail_rows: list[Adw.ActionRow]
    _audit_group: Adw.PreferencesGroup
    update_all_btn: Gtk.Button
    bootstrap_btn: Gtk.Button
    maintenance_only_btn: Gtk.Button
    post_update_btn: Gtk.Button
    rkh_update_btn: Gtk.Button
    rkh_propupd_btn: Gtk.Button
    maintenance_status_row: Adw.ActionRow
    realtime_group: Adw.PreferencesGroup
    clamonacc_row: Adw.SwitchRow
    _path_action_rows: list[Adw.ActionRow]
    services_group: Adw.PreferencesGroup
    _refresh_services: Callable[[], None]

    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window | None = None,
        on_status: Callable[[str], None] | None = None,
        on_setup_wizard: Callable[[], None] | None = None,
        on_security_news_changed: Callable[[], None] | None = None,
        on_updates_changed: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self._window = window
        self._on_status = on_status
        self._on_setup_wizard_cb = on_setup_wizard
        self._on_security_news_changed = on_security_news_changed
        self._on_updates_changed = on_updates_changed
        self._loading = True
        self._schedule_apply_timeout = 0
        self._schedule_applying = False
        self._linger_prompted = False
        self._section_pages: dict[str, Adw.PreferencesPage] = {}

        self.pack_list = PackListWidget(
            client,
            window=window,
            on_status=on_status,
            on_changed=self._on_packs_changed,
        )

        self._sidebar = Gtk.ListBox()
        self._sidebar.set_size_request(180, -1)
        self._sidebar.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._sidebar.add_css_class("navigation-sidebar")
        for _section_id, title in SETTINGS_SECTIONS:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label=title, xalign=0, margin_start=12, margin_end=12))
            self._sidebar.append(row)
        self._sidebar.connect("row-selected", self._on_sidebar_selected)

        self._stack = Gtk.Stack()
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        settings_general_ui.build_general_section(self)
        self._build_services_section()
        self._build_realtime_section()
        settings_schedule_ui.build_schedule_group(self)
        settings_host_audit_ui.build_host_audit_section(self)
        settings_maintenance_ui.build_maintenance_group(self)
        self._build_packs_section()

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True)
        paned.set_start_child(self._sidebar)
        paned.set_end_child(self._stack)
        paned.set_shrink_start_child(False)
        paned.set_shrink_end_child(False)
        paned.set_resize_start_child(False)
        paned.set_resize_end_child(True)
        paned.set_position(190)
        paned.set_hexpand(True)
        paned.set_vexpand(True)

        self.widget = paned
        self.show_section("general")

    def _add_section_page(self, section_id: str, page: Adw.PreferencesPage) -> None:
        self._section_pages[section_id] = page
        self._stack.add_named(make_scrolled_page(page), section_id)

    def _on_sidebar_selected(self, _box: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            return
        index = row.get_index()
        if 0 <= index < len(SETTINGS_SECTIONS):
            self._stack.set_visible_child_name(SETTINGS_SECTIONS[index][0])

    def show_section(self, section: str | None = None) -> None:
        """Select a Settings sidebar section (default: General)."""
        section_id = section if section in SETTINGS_SECTION_IDS else "general"
        self._stack.set_visible_child_name(section_id)
        for index, (sid, _) in enumerate(SETTINGS_SECTIONS):
            if sid == section_id:
                row = self._sidebar.get_row_at_index(index)
                if row is not None:
                    self._sidebar.select_row(row)
                break

    def _build_services_section(self) -> None:
        page = Adw.PreferencesPage()
        self.services_group, self._refresh_services = build_services_group(
            self.client,
            window=self._window,
            on_status=self._on_status,
        )
        page.add(self.services_group)
        self._add_section_page("services", page)

    def _build_realtime_section(self) -> None:
        page = Adw.PreferencesPage()
        self.realtime_group = Adw.PreferencesGroup(title="Real-time monitoring")
        self.clamonacc_row = Adw.SwitchRow(title="Clamonacc monitoring")
        self.clamonacc_row.set_subtitle(
            "Start/stop on-access scanning and persist clamonacc.enabled "
            "(paths below; Services shows status only)",
        )
        self.clamonacc_row.connect("notify::active", self._on_clamonacc_saved)
        self.realtime_group.add(self.clamonacc_row)

        self._path_action_rows: list[Adw.ActionRow] = []
        add_path_btn = make_button("Add path…", row_suffix=True)
        add_path_btn.connect("clicked", self._on_add_clamonacc_path)
        add_path_row = Adw.ActionRow(title="Add watched folder")
        add_path_row.set_subtitle("Folders for on-access scanning")
        add_path_row.add_suffix(add_path_btn)
        self.realtime_group.add(add_path_row)
        page.add(self.realtime_group)
        self._add_section_page("realtime", page)

    def _build_packs_section(self) -> None:
        page = Adw.PreferencesPage()
        self.pack_list.attach_to_page(page)
        self._add_section_page("packs", page)

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window
        self.pack_list.set_window(window)

    def _on_packs_changed(self) -> None:
        """Packs already refreshed in PackListWidget; only refresh pack-dependent rows."""
        refresh_clamonacc_subtitle(self.client, self.clamonacc_row)

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def refresh(self) -> None:
        run_in_thread(self._load_data, self._apply_data, self._apply_error)
        self._refresh_services()
        settings_host_audit_ui.refresh_audit(self)
        settings_host_audit_ui.refresh_host_security(self)

    def _load_data(self) -> dict[str, Any]:
        config = self.client.config_get()
        packs = self.client.doctor()
        schedule = self.client.schedule_status()
        runtime = self.client.runtime_status()
        desktop = self.client.desktop_status()
        return {
            "config": config,
            "packs": packs,
            "schedule": schedule,
            "runtime": runtime,
            "desktop": desktop,
        }

    def _apply_data(self, data: dict[str, Any]) -> bool:
        return apply_settings_data(self, data)

    def _apply_error(self, message: str) -> bool:
        self.backend_status_row.set_subtitle(f"Not connected — {message}")
        self._set_status(f"Settings error: {message}")
        self._loading = False
        return False

    def _populate_clamonacc_paths(self, paths: list[str]) -> None:
        populate_clamonacc_paths(
            self.realtime_group,
            self._path_action_rows,
            paths,
            on_remove=self._on_remove_clamonacc_path,
        )

    def _on_add_clamonacc_path(self, *_args: object) -> None:
        add_clamonacc_path_from_dialog(
            self.client,
            window=self._window,
            on_status=self._set_status,
            on_complete=self.refresh,
        )

    def _on_remove_clamonacc_path(self, path: str) -> None:
        remove_clamonacc_path_from_gui(
            self.client,
            path,
            on_status=self._set_status,
            on_complete=self.refresh,
        )

    def _save(self, key: str, value: str) -> None:
        if self._loading:
            return

        def done(_: object) -> bool:
            self._set_status(f"Saved {key}")
            if key.startswith("schedule."):
                settings_schedule_ui.queue_timer_apply(self)
            return False

        run_in_thread(
            lambda: self.client.config_set(key, value),
            done,
            self._apply_error,
        )

    def _selected_option(self, row: Adw.ComboRow, options: list[str]) -> str | None:
        idx = int(row.get_selected())
        if 0 <= idx < len(options):
            return options[idx]
        return None

    def _on_clamonacc_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        if self._loading:
            return
        if row.get_active():
            enable_clamonacc_from_gui(
                self.client,
                window=self._window,
                on_status=self._set_status,
                on_complete=self.refresh,
            )
        else:
            disable_clamonacc_from_gui(
                self.client,
                window=self._window,
                on_status=self._set_status,
                on_complete=self.refresh,
            )

    def _on_schedule_run_now(self, *_args: object) -> None:
        self._schedule_run_btn.set_sensitive(False)
        self._set_status("Running scheduled scan…")

        def worker() -> dict[str, Any]:
            return self.client.schedule_run()

        def on_complete(result: dict[str, Any]) -> bool:
            self._schedule_run_btn.set_sensitive(True)
            scan_raw = result.get("scan")
            scan = scan_raw if isinstance(scan_raw, dict) else {}
            findings_raw = scan.get("findings")
            findings = findings_raw if isinstance(findings_raw, list) else []
            errors_raw = scan.get("pack_errors")
            errors = errors_raw if isinstance(errors_raw, list) else []
            if result.get("ok"):
                body = (
                    f"Finished with {len(findings)} finding(s)."
                    if findings
                    else "Finished — no findings."
                )
                if errors:
                    body += f"\n{len(errors)} pack error(s) reported."
                body += "\n\nOpen the Scan or Quarantine tab for details."
                show_command_dialog(self._window, heading="Scheduled scan complete", body=body)
                self._set_status("Scheduled scan complete")
            else:
                msg = str(result.get("message") or f"Exit code {result.get('exit_code', '?')}")
                show_command_dialog(self._window, heading="Scheduled scan failed", body=msg)
                self._set_status("Scheduled scan failed")
            return False

        def on_error(message: str) -> bool:
            self._schedule_run_btn.set_sensitive(True)
            show_command_dialog(
                self._window,
                heading="Scheduled scan failed",
                body=message,
            )
            self._set_status(f"Scheduled scan failed: {message}")
            return False

        run_in_thread(worker, on_complete, on_error)
