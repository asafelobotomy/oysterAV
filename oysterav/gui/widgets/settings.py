"""Settings tab — user preferences."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import PROFILE_PACKS, PROFILE_PATHS, ScanProfile
from oyst_core.security_news import NEWS_SOURCES
from oyst_core.ui_theme import DEFAULT_UI_THEME, UI_THEME_IDS, UI_THEME_LABELS
from oysterav.gui.rpc_actions import (
    request_audit_list,
    request_fail2ban_unban,
    request_firewall_status,
    request_news_refresh,
    request_updates_apply,
)
from oysterav.gui.theme import apply_theme
from oysterav.gui.widgets.clamonacc_ui import (
    add_clamonacc_path_from_dialog,
    disable_clamonacc_from_gui,
    enable_clamonacc_from_gui,
    refresh_clamonacc_subtitle,
    remove_clamonacc_path_from_gui,
)
from oysterav.gui.widgets.common import (
    bind_string_combo_row,
    make_button,
    make_scrolled_page,
    run_in_thread,
    show_command_dialog,
)
from oysterav.gui.widgets.packs import PackListWidget
from oysterav.gui.widgets.progress_button import run_progress_button
from oysterav.gui.widgets.runtime_ui import bootstrap_runtime_from_gui
from oysterav.gui.widgets.schedule_ui import (
    format_timer_status,
    show_schedule_result,
)
from oysterav.gui.widgets.services_ui import build_services_group


_SCHEDULE_PROFILE_OPTIONS = [p.value for p in ScanProfile]
_SCHEDULE_PROFILE_LABELS = [
    {
        ScanProfile.QUICK: "Quick",
        ScanProfile.FULL: "Full",
        ScanProfile.INTEGRITY: "Integrity",
        ScanProfile.SUITE: "Suite",
        ScanProfile.CUSTOM: "Custom",
    }.get(p, p.value)
    for p in ScanProfile
]
_BACKEND_OPTIONS = ["auto", "clamd", "clamscan"]
_SCHED_BACKEND_OPTIONS = ["inherit", "auto", "clamd", "clamscan"]
_SCHED_BACKEND_LABELS = [
    "Inherit (use General scan backend)",
    "auto",
    "clamd",
    "clamscan",
]
_THEME_OPTIONS: list[str] = list(UI_THEME_IDS)
_THEME_LABELS = [UI_THEME_LABELS[t] for t in UI_THEME_IDS]
_FREQUENCY_OPTIONS = ["hourly", "daily", "weekly", "custom"]
_FREQUENCY_LABELS = ["Hourly", "Daily", "Weekly", "Custom"]
_WEEKDAY_OPTIONS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_WEEKDAY_LABELS = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
]
_QUARANTINE_OPTIONS = ["auto", "on", "off"]
_QUARANTINE_LABELS = ["Auto (follow General)", "Always on", "Always off"]
_SCHEDULE_APPLY_DEBOUNCE_MS = 700

# Sidebar section id → label (order is navigation order).
SETTINGS_SECTIONS: tuple[tuple[str, str], ...] = (
    ("general", "General"),
    ("services", "Services"),
    ("realtime", "Real-time"),
    ("scheduling", "Scheduling"),
    ("host_audit", "Host & audit"),
    ("maintenance", "Maintenance"),
    ("packs", "Security packs"),
)
_SETTINGS_SECTION_IDS = {section_id for section_id, _ in SETTINGS_SECTIONS}


class SettingsPage:
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

        self._build_general_section()
        self._build_services_section()
        self._build_realtime_section()
        self._build_schedule_group()
        self._build_host_audit_section()
        self._build_maintenance_group()
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
        section_id = section if section in _SETTINGS_SECTION_IDS else "general"
        self._stack.set_visible_child_name(section_id)
        for index, (sid, _) in enumerate(SETTINGS_SECTIONS):
            if sid == section_id:
                row = self._sidebar.get_row_at_index(index)
                if row is not None:
                    self._sidebar.select_row(row)
                break

    def _build_general_section(self) -> None:
        page = Adw.PreferencesPage()
        general = Adw.PreferencesGroup(title="General")

        self.backend_status_row = Adw.ActionRow(title="oyst-cli backend")
        self.backend_status_row.set_subtitle("Checking connection…")
        self.backend_status_row.set_sensitive(False)
        general.add(self.backend_status_row)

        self.security_news_row = Adw.SwitchRow(title="Security news ticker")
        self.security_news_row.set_subtitle(
            "Scroll selected advisories in the status bar (severity-prioritized, updated daily)",
        )
        self.security_news_row.connect("notify::active", self._on_security_news_saved)
        general.add(self.security_news_row)

        news_refresh_row = Adw.ActionRow(title="Refresh security news")
        news_refresh_row.set_subtitle("Force-refresh selected advisory feeds now")
        news_refresh_btn = make_button("Refresh", row_suffix=True)
        news_refresh_btn.connect("clicked", self._on_news_refresh)
        news_refresh_row.add_suffix(news_refresh_btn)
        general.add(news_refresh_row)

        page.add(general)

        sources_group = Adw.PreferencesGroup(
            title="News sources",
            description="Enable one or more feeds. Highest-severity headlines appear first.",
        )
        self._news_source_rows: dict[str, Adw.SwitchRow] = {}
        _source_subtitles = {
            "arch": "Arch Linux Security Advisories (ASA)",
            "ubuntu": "Ubuntu Security Notices (USN)",
            "debian": "Debian Security Advisories (DSA)",
            "gentoo": "Gentoo Linux Security Advisories (GLSA)",
            "fedora": "Fedora Bodhi security updates",
            "oss-security": "Open Source Security mailing list (seclists)",
        }
        for sid, src in NEWS_SOURCES.items():
            row = Adw.SwitchRow(title=src.label)
            row.set_subtitle(_source_subtitles.get(sid, src.url))
            row.connect("notify::active", self._on_news_sources_saved)
            sources_group.add(row)
            self._news_source_rows[sid] = row
        page.add(sources_group)

        general_scan = Adw.PreferencesGroup(title="Scan defaults")

        self.auto_quarantine_row = Adw.SwitchRow(title="Auto-quarantine threats")
        self.auto_quarantine_row.set_subtitle(
            "Default after scans; Scheduling can override for the timer",
        )
        self.auto_quarantine_row.connect("notify::active", self._on_auto_quarantine_saved)
        general_scan.add(self.auto_quarantine_row)

        self.profile_row = Adw.ComboRow(title="Default scan profile")
        self.profile_row.set_subtitle(
            "Default for the Scan tab and `oyst-cli scan` when --profile is omitted",
        )
        bind_string_combo_row(self.profile_row, _SCHEDULE_PROFILE_LABELS)
        self.profile_row.connect("notify::selected", self._on_profile_saved)
        general_scan.add(self.profile_row)

        self.backend_row = Adw.ComboRow(title="Scan backend")
        self.backend_row.set_subtitle(
            "Default for manual scans (prefer clamd); Scheduling can inherit this",
        )
        bind_string_combo_row(self.backend_row, _BACKEND_OPTIONS)
        self.backend_row.connect("notify::selected", self._on_backend_saved)
        general_scan.add(self.backend_row)

        self.theme_row = Adw.ComboRow(title="Theme")
        self.theme_row.set_subtitle("Application colors (default: Gruvbox Dark Hard)")
        bind_string_combo_row(self.theme_row, _THEME_LABELS)
        self.theme_row.connect("notify::selected", self._on_theme_saved)
        general_scan.add(self.theme_row)

        self.run_at_startup_row = Adw.SwitchRow(title="Run at startup")
        self.run_at_startup_row.set_subtitle("Launch oysterAV when you log in (XDG autostart)")
        self.run_at_startup_row.connect("notify::active", self._on_run_at_startup_saved)
        general_scan.add(self.run_at_startup_row)

        self.start_minimized_row = Adw.SwitchRow(title="Start minimized")
        self.start_minimized_row.set_subtitle("Hide the window on launch (requires a working tray)")
        self.start_minimized_row.connect("notify::active", self._on_start_minimized_saved)
        general_scan.add(self.start_minimized_row)

        self.minimize_to_tray_row = Adw.SwitchRow(title="Minimize to tray on close")
        self.minimize_to_tray_row.set_subtitle(
            "Close hides oysterAV in the tray instead of quitting",
        )
        self.minimize_to_tray_row.connect("notify::active", self._on_minimize_to_tray_saved)
        general_scan.add(self.minimize_to_tray_row)

        page.add(general_scan)
        self._add_section_page("general", page)

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

    def _build_schedule_group(self) -> None:
        page = Adw.PreferencesPage()
        schedule = Adw.PreferencesGroup(title="Scheduling")
        schedule.set_description(
            "Configure when and what the systemd user timer scans. "
            "Changes save automatically and update the timer.",
        )

        self.schedule_status_row = Adw.ActionRow(title="Timer status")
        self.schedule_status_row.set_subtitle("Loading…")
        schedule.add(self.schedule_status_row)

        self.sched_enabled_row = Adw.SwitchRow(title="Enable scheduled scan")
        self.sched_enabled_row.set_subtitle("Enable or disable the systemd user timer")
        self.sched_enabled_row.connect("notify::active", self._on_sched_enabled_saved)
        schedule.add(self.sched_enabled_row)

        self.sched_profile_row = Adw.ComboRow(title="Scan profile")
        self.sched_profile_row.set_subtitle("Preset packs and paths (custom needs packs)")
        bind_string_combo_row(self.sched_profile_row, _SCHEDULE_PROFILE_LABELS)
        self.sched_profile_row.connect("notify::selected", self._on_sched_profile_saved)
        schedule.add(self.sched_profile_row)

        self.sched_frequency_row = Adw.ComboRow(title="Frequency")
        self.sched_frequency_row.set_subtitle("How often the user timer fires")
        bind_string_combo_row(self.sched_frequency_row, _FREQUENCY_LABELS)
        self.sched_frequency_row.connect("notify::selected", self._on_sched_frequency_saved)
        schedule.add(self.sched_frequency_row)

        self.sched_time_row = Adw.EntryRow(title="Time (HH:MM)")
        self.sched_time_row.set_tooltip_text("Local time for daily and weekly schedules")
        self.sched_time_row.set_show_apply_button(True)
        self.sched_time_row.connect("apply", self._on_sched_time_saved)
        schedule.add(self.sched_time_row)

        self.sched_weekday_row = Adw.ComboRow(title="Weekday")
        self.sched_weekday_row.set_subtitle("Used when frequency is weekly")
        bind_string_combo_row(self.sched_weekday_row, _WEEKDAY_LABELS)
        self.sched_weekday_row.connect("notify::selected", self._on_sched_weekday_saved)
        schedule.add(self.sched_weekday_row)

        self.sched_calendar_row = Adw.EntryRow(title="Custom OnCalendar")
        self.sched_calendar_row.set_tooltip_text(
            "Required when frequency is Custom. Example: *-*-* 03:30:00. "
            "Press the row checkmark to save.",
        )
        self.sched_calendar_row.set_show_apply_button(True)
        self.sched_calendar_row.connect("apply", self._on_sched_calendar_saved)
        schedule.add(self.sched_calendar_row)

        self.sched_packs_row = Adw.EntryRow(title="Packs override")
        self.sched_packs_row.set_tooltip_text(
            "Comma-separated packs; empty uses the profile default. "
            "Press the row checkmark to save.",
        )
        self.sched_packs_row.set_show_apply_button(True)
        self.sched_packs_row.connect("apply", self._on_sched_packs_saved)
        schedule.add(self.sched_packs_row)

        self.sched_paths_row = Adw.EntryRow(title="Paths override")
        self.sched_paths_row.set_tooltip_text(
            "Comma-separated paths; empty uses the profile default. "
            "Press the row checkmark to save.",
        )
        self.sched_paths_row.set_show_apply_button(True)
        self.sched_paths_row.connect("apply", self._on_sched_paths_saved)
        schedule.add(self.sched_paths_row)

        self.sched_quarantine_row = Adw.ComboRow(title="Quarantine")
        self.sched_quarantine_row.set_subtitle(
            "Timer override — Auto follows General auto-quarantine",
        )
        bind_string_combo_row(self.sched_quarantine_row, _QUARANTINE_LABELS)
        self.sched_quarantine_row.connect("notify::selected", self._on_sched_quarantine_saved)
        schedule.add(self.sched_quarantine_row)

        self.sched_backend_row = Adw.ComboRow(title="Scan backend")
        self.sched_backend_row.set_subtitle(
            "Timer override — Inherit follows General scan backend",
        )
        bind_string_combo_row(self.sched_backend_row, _SCHED_BACKEND_LABELS)
        self.sched_backend_row.connect("notify::selected", self._on_sched_backend_saved)
        schedule.add(self.sched_backend_row)

        self.sched_persistent_row = Adw.SwitchRow(title="Catch up missed runs")
        self.sched_persistent_row.set_subtitle(
            "Run missed scans after boot or login (systemd Persistent=true)",
        )
        self.sched_persistent_row.connect("notify::active", self._on_sched_persistent_saved)
        schedule.add(self.sched_persistent_row)

        run_row = Adw.ActionRow(title="Run scheduled scan now")
        run_row.set_subtitle(
            "Runs once with the current saved schedule (does not change the timer)",
        )
        self._schedule_run_btn = make_button("Run now", suggested=True, row_suffix=True)
        self._schedule_run_btn.connect("clicked", self._on_schedule_run_now)
        run_row.add_suffix(self._schedule_run_btn)
        schedule.add(run_row)

        page.add(schedule)
        self._add_section_page("scheduling", page)

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
        self._refresh_audit()
        self._refresh_host_security()

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
        self._loading = True
        config = data.get("config")
        if not isinstance(config, dict):
            self.backend_status_row.set_subtitle("Not connected — invalid config response")
            self._loading = False
            return False

        self.backend_status_row.set_subtitle("Connected")

        runtime_status = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
        self.pack_list.set_packs(list(data.get("packs", [])), runtime=runtime_status)

        quarantine = config.get("quarantine", {})
        self.auto_quarantine_row.set_active(bool(quarantine.get("auto")))

        scan_cfg = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
        profile = str(scan_cfg.get("profile", "quick"))
        if profile in _SCHEDULE_PROFILE_OPTIONS:
            self.profile_row.set_selected(_SCHEDULE_PROFILE_OPTIONS.index(profile))

        backend = scan_cfg.get("backend", "auto")
        if backend in _BACKEND_OPTIONS:
            self.backend_row.set_selected(_BACKEND_OPTIONS.index(backend))

        ui_raw = config.get("ui")
        ui = ui_raw if isinstance(ui_raw, dict) else {}
        self.security_news_row.set_active(bool(ui.get("security_news", True)))
        raw_sources = ui.get("security_news_sources")
        enabled_sources = (
            {str(s) for s in raw_sources}
            if isinstance(raw_sources, list)
            else {"arch", "ubuntu", "debian"}
        )
        for sid, row in self._news_source_rows.items():
            row.set_active(sid in enabled_sources)
        self._sync_news_source_sensitivity()
        theme = str(ui.get("theme", DEFAULT_UI_THEME))
        if theme in _THEME_OPTIONS:
            self.theme_row.set_selected(_THEME_OPTIONS.index(theme))
        else:
            self.theme_row.set_selected(_THEME_OPTIONS.index(DEFAULT_UI_THEME))
        self.run_at_startup_row.set_active(bool(ui.get("run_at_startup")))
        self.start_minimized_row.set_active(bool(ui.get("start_minimized")))
        self.minimize_to_tray_row.set_active(bool(ui.get("minimize_to_tray")))
        desktop_raw = data.get("desktop")
        tray = desktop_raw if isinstance(desktop_raw, dict) else {}
        tray_info_raw = tray.get("tray")
        tray_info = tray_info_raw if isinstance(tray_info_raw, dict) else {}
        if not tray_info.get("available", True):
            hint = str(tray_info.get("hint") or "Tray host unavailable")
            self.start_minimized_row.set_subtitle(f"Requires a working tray — {hint}")
            self.minimize_to_tray_row.set_subtitle(
                f"Close hides to tray when available — {hint}",
            )
        else:
            self.start_minimized_row.set_subtitle(
                "Hide the window on launch (requires a working tray)",
            )
            self.minimize_to_tray_row.set_subtitle(
                "Close hides oysterAV in the tray instead of quitting",
            )

        clamonacc = config.get("clamonacc", {})
        self.clamonacc_row.set_active(bool(clamonacc.get("enabled")))
        refresh_clamonacc_subtitle(self.client, self.clamonacc_row)
        self._populate_clamonacc_paths(clamonacc.get("paths", []))

        schedule_status = data.get("schedule", {})
        sched_cfg = config.get("schedule", {})
        if not isinstance(sched_cfg, dict) and isinstance(schedule_status, dict):
            raw = schedule_status.get("config")
            sched_cfg = raw if isinstance(raw, dict) else {}
        if isinstance(sched_cfg, dict):
            self._apply_schedule_config(sched_cfg)
        if isinstance(schedule_status, dict):
            self._apply_schedule_status(schedule_status)

        self._loading = False
        return False

    def _apply_error(self, message: str) -> bool:
        self.backend_status_row.set_subtitle(f"Not connected — {message}")
        self._set_status(f"Settings error: {message}")
        self._loading = False
        return False

    def _apply_schedule_config(self, cfg: dict[str, Any]) -> None:
        self.sched_enabled_row.set_active(bool(cfg.get("enabled")))

        profile = str(cfg.get("profile", "quick"))
        if profile in _SCHEDULE_PROFILE_OPTIONS:
            self.sched_profile_row.set_selected(_SCHEDULE_PROFILE_OPTIONS.index(profile))

        freq = str(cfg.get("frequency", "daily"))
        if freq in _FREQUENCY_OPTIONS:
            self.sched_frequency_row.set_selected(_FREQUENCY_OPTIONS.index(freq))

        self.sched_time_row.set_text(str(cfg.get("time", "02:00")))

        weekday = str(cfg.get("weekday", "mon")).lower()
        if weekday in _WEEKDAY_OPTIONS:
            self.sched_weekday_row.set_selected(_WEEKDAY_OPTIONS.index(weekday))

        self.sched_calendar_row.set_text(str(cfg.get("on_calendar", "")))
        packs = cfg.get("packs") or []
        paths = cfg.get("paths") or []
        self.sched_packs_row.set_text(",".join(str(p) for p in packs) if packs else "")
        self.sched_paths_row.set_text(",".join(str(p) for p in paths) if paths else "")
        self._update_schedule_override_hints(profile)

        quarantine = str(cfg.get("quarantine", "auto"))
        if quarantine in _QUARANTINE_OPTIONS:
            self.sched_quarantine_row.set_selected(_QUARANTINE_OPTIONS.index(quarantine))

        backend = str(cfg.get("backend", "inherit"))
        if backend in _SCHED_BACKEND_OPTIONS:
            self.sched_backend_row.set_selected(_SCHED_BACKEND_OPTIONS.index(backend))

        self.sched_persistent_row.set_active(bool(cfg.get("persistent", True)))
        self._update_schedule_row_sensitivity(freq)
        if freq == "custom":
            self._seed_custom_on_calendar_if_empty()

    def _update_schedule_override_hints(self, profile: str) -> None:
        try:
            sp = ScanProfile(profile)
        except ValueError:
            sp = ScanProfile.QUICK
        pack_default = ", ".join(PROFILE_PACKS.get(sp, [])) or "(none)"
        path_default = ", ".join(PROFILE_PATHS.get(sp, [])) or "(none)"
        self.sched_packs_row.set_title(f"Packs override (default: {pack_default})")
        self.sched_paths_row.set_title(f"Paths override (default: {path_default})")

    def _update_schedule_row_sensitivity(self, frequency: str) -> None:
        self.sched_time_row.set_sensitive(frequency in ("daily", "weekly"))
        self.sched_weekday_row.set_sensitive(frequency == "weekly")
        self.sched_calendar_row.set_sensitive(frequency == "custom")
        if frequency == "custom":
            self.sched_calendar_row.set_title("Custom OnCalendar (required)")
        else:
            self.sched_calendar_row.set_title("Custom OnCalendar")

    def _seed_custom_on_calendar_if_empty(self) -> None:
        """When switching to Custom, seed a valid OnCalendar from the time field."""
        if self.sched_calendar_row.get_text().strip():
            return
        at_time = self.sched_time_row.get_text().strip() or "02:00"
        try:
            hour_s, minute_s = at_time.split(":", 1)
            hour, minute = int(hour_s), int(minute_s)
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError
            seeded = f"*-*-* {hour:02d}:{minute:02d}:00"
        except ValueError:
            seeded = "*-*-* 02:00:00"
        self.sched_calendar_row.set_text(seeded)
        if not self._loading:
            self._save("schedule.on_calendar", seeded)

    def _schedule_validation_error(self) -> str | None:
        """Return a user-facing error if current UI values cannot be saved."""
        frequency = self._selected_option(self.sched_frequency_row, _FREQUENCY_OPTIONS) or "daily"
        profile = (
            self._selected_option(self.sched_profile_row, _SCHEDULE_PROFILE_OPTIONS) or "quick"
        )
        on_calendar = self.sched_calendar_row.get_text().strip()
        packs = self.sched_packs_row.get_text().strip()
        if frequency == "custom" and not on_calendar:
            return (
                "Frequency is Custom, but Custom OnCalendar is empty.\n\n"
                "Enter a systemd OnCalendar expression such as:\n"
                "*-*-* 03:30:00"
            )
        if profile == "custom" and not packs:
            return (
                "Scan profile is Custom, but Packs override is empty.\n\n"
                "Add one or more packs (comma-separated), for example:\n"
                "clamav,rkhunter"
            )
        return None

    def _show_schedule_validation_dialog(self, body: str) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self._window,
            heading="Cannot update schedule timer",
            body=body,
        )
        dialog.add_response("ok", "OK")
        dialog.set_default_response("ok")
        dialog.set_close_response("ok")
        dialog.present()

    def _apply_schedule_status(self, status: dict[str, Any]) -> None:
        self.schedule_status_row.set_subtitle(format_timer_status(status))

    def _populate_clamonacc_paths(self, paths: list[str]) -> None:
        for row in self._path_action_rows:
            self.realtime_group.remove(row)
        self._path_action_rows.clear()
        if not paths:
            empty = Adw.ActionRow(title="No watched paths configured")
            empty.set_subtitle("Add folders for on-access scanning")
            self.realtime_group.add(empty)
            self._path_action_rows.append(empty)
            return
        for path in paths:
            action = Adw.ActionRow()
            action.set_title(str(path))
            remove_btn = make_button("Remove", destructive=True, row_suffix=True)
            remove_btn.connect(
                "clicked",
                lambda _btn, p=str(path): self._on_remove_clamonacc_path(p),
            )
            action.add_suffix(remove_btn)
            self.realtime_group.add(action)
            self._path_action_rows.append(action)

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
                self._queue_timer_apply()
            return False

        run_in_thread(
            lambda: self.client.config_set(key, value),
            done,
            self._apply_error,
        )

    def _queue_timer_apply(self) -> None:
        """Debounce systemd timer materialization after schedule config changes."""
        if self._schedule_apply_timeout:
            GLib.source_remove(self._schedule_apply_timeout)
            self._schedule_apply_timeout = 0
        self._schedule_apply_timeout = GLib.timeout_add(
            _SCHEDULE_APPLY_DEBOUNCE_MS,
            self._run_timer_apply,
        )

    def _run_timer_apply(self) -> bool:
        self._schedule_apply_timeout = 0
        if self._loading:
            return False
        validation = self._schedule_validation_error()
        if validation:
            self._show_schedule_validation_dialog(validation)
            return False
        if self._schedule_applying:
            self._queue_timer_apply()
            return False

        self._schedule_applying = True
        self._schedule_run_btn.set_sensitive(False)

        def worker() -> dict[str, Any]:
            return self.client.schedule_apply(smoke_test=True)

        def on_complete(result: dict[str, Any]) -> bool:
            self._schedule_applying = False
            self._schedule_run_btn.set_sensitive(True)
            if not result.get("ok"):
                show_command_dialog(
                    self._window,
                    heading="Could not update schedule timer",
                    body=str(result.get("message", "Schedule apply failed")),
                    copy_text=str(result.get("enable_hint") or "") or None,
                )
                self.refresh()
                return False

            message = str(result.get("message", "Schedule timer updated"))
            self._set_status(message)
            self.refresh()

            linger = result.get("linger") if isinstance(result.get("linger"), dict) else {}
            advisory = result.get("linger_advisory")
            if (
                result.get("enabled")
                and advisory
                and isinstance(linger, dict)
                and not linger.get("linger", True)
                and not self._linger_prompted
            ):
                self._linger_prompted = True
                show_schedule_result(
                    self._window,
                    result,
                    on_status=self._set_status,
                    client=self.client,
                )
            return False

        def on_error(message: str) -> bool:
            self._schedule_applying = False
            self._schedule_run_btn.set_sensitive(True)
            return self._apply_error(message)

        run_in_thread(worker, on_complete, on_error)
        return False

    def _selected_option(self, row: Adw.ComboRow, options: list[str]) -> str | None:
        idx = int(row.get_selected())
        if 0 <= idx < len(options):
            return options[idx]
        return None

    def _sync_news_source_sensitivity(self) -> None:
        enabled = bool(self.security_news_row.get_active())
        for row in self._news_source_rows.values():
            row.set_sensitive(enabled)

    def _on_security_news_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        if self._loading:
            return
        self._save("ui.security_news", "true" if row.get_active() else "false")
        self._sync_news_source_sensitivity()
        if self._on_security_news_changed:
            self._on_security_news_changed()

    def _on_news_sources_saved(self, *_args: object) -> None:
        if self._loading:
            return
        selected = [sid for sid, row in self._news_source_rows.items() if row.get_active()]
        if not selected:
            # Keep at least one source — re-enable Arch and persist defaults.
            self._loading = True
            for sid, row in self._news_source_rows.items():
                row.set_active(sid in ("arch", "ubuntu", "debian"))
            self._loading = False
            selected = ["arch", "ubuntu", "debian"]
            self._set_status("At least one news source is required")

        def done(_: object) -> bool:
            self._set_status("Saved ui.security_news_sources")
            if self._on_security_news_changed:
                # Force refresh so the ticker matches the new selection.
                self._on_news_refresh()
            return False

        run_in_thread(
            lambda: self.client.config_set("ui.security_news_sources", ",".join(selected)),
            done,
            self._apply_error,
        )

    def _on_auto_quarantine_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        val = "true" if row.get_active() else "false"
        self._save("quarantine.auto", val)

    def _on_profile_saved(self, *_args: object) -> None:
        value = self._selected_option(self.profile_row, _SCHEDULE_PROFILE_OPTIONS)
        if value:
            self._save("scan.profile", value)

    def _on_backend_saved(self, *_args: object) -> None:
        value = self._selected_option(self.backend_row, _BACKEND_OPTIONS)
        if value:
            self._save("scan.backend", value)

    def _on_theme_saved(self, *_args: object) -> None:
        if self._loading:
            return
        theme_id = self._selected_option(self.theme_row, _THEME_OPTIONS)
        if theme_id:
            self._save("ui.theme", theme_id)
            apply_theme(theme_id)

    def _on_run_at_startup_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        self._save("ui.run_at_startup", "true" if row.get_active() else "false")

    def _on_start_minimized_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        self._save("ui.start_minimized", "true" if row.get_active() else "false")

    def _on_minimize_to_tray_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        self._save("ui.minimize_to_tray", "true" if row.get_active() else "false")

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
                on_status=self._set_status,
                on_complete=self.refresh,
            )

    def _on_sched_enabled_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        self._save("schedule.enabled", "true" if row.get_active() else "false")

    def _on_sched_profile_saved(self, *_args: object) -> None:
        value = self._selected_option(self.sched_profile_row, _SCHEDULE_PROFILE_OPTIONS)
        if value:
            self._save("schedule.profile", value)
            self._update_schedule_override_hints(value)

    def _on_sched_frequency_saved(self, *_args: object) -> None:
        value = self._selected_option(self.sched_frequency_row, _FREQUENCY_OPTIONS)
        if value:
            self._save("schedule.frequency", value)
            self._update_schedule_row_sensitivity(value)
            if value == "custom":
                self._seed_custom_on_calendar_if_empty()

    def _on_sched_time_saved(self, row: Adw.EntryRow, *_args: object) -> None:
        text = row.get_text().strip()
        if text:
            self._save("schedule.time", text)

    def _on_sched_weekday_saved(self, *_args: object) -> None:
        value = self._selected_option(self.sched_weekday_row, _WEEKDAY_OPTIONS)
        if value:
            self._save("schedule.weekday", value)

    def _on_sched_calendar_saved(self, row: Adw.EntryRow, *_args: object) -> None:
        self._save("schedule.on_calendar", row.get_text().strip())

    def _on_sched_packs_saved(self, row: Adw.EntryRow, *_args: object) -> None:
        self._save("schedule.packs", row.get_text().strip())

    def _on_sched_paths_saved(self, row: Adw.EntryRow, *_args: object) -> None:
        self._save("schedule.paths", row.get_text().strip())

    def _on_sched_quarantine_saved(self, *_args: object) -> None:
        value = self._selected_option(self.sched_quarantine_row, _QUARANTINE_OPTIONS)
        if value:
            self._save("schedule.quarantine", value)

    def _on_sched_backend_saved(self, *_args: object) -> None:
        value = self._selected_option(self.sched_backend_row, _SCHED_BACKEND_OPTIONS)
        if value:
            self._save("schedule.backend", value)

    def _on_sched_persistent_saved(self, row: Adw.SwitchRow, *_args: object) -> None:
        self._save("schedule.persistent", "true" if row.get_active() else "false")

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
                if findings:
                    body = f"Finished with {len(findings)} finding(s)."
                else:
                    body = "Finished — no findings."
                if errors:
                    body += f"\n{len(errors)} pack error(s) reported."
                body += "\n\nOpen the Scan or Quarantine tab for details."
                show_command_dialog(
                    self._window,
                    heading="Scheduled scan complete",
                    body=body,
                )
                self._set_status("Scheduled scan complete")
            else:
                show_command_dialog(
                    self._window,
                    heading="Scheduled scan failed",
                    body=str(result.get("message") or f"Exit code {result.get('exit_code', '?')}"),
                )
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

    def _build_maintenance_group(self) -> None:
        page = Adw.PreferencesPage()
        maintenance = Adw.PreferencesGroup(title="Maintenance")
        maintenance.set_description(
            "Install or refresh the private runtime, virus signatures, and baselines. "
            "Maintenance only may refresh the rkhunter baseline without a separate confirm.",
        )

        update_all_row = Adw.ActionRow(title="Update all")
        update_all_row.set_subtitle(
            "Check pack/service packages, upgrade when needed, refresh definitions, "
            "then post-update baseline",
        )
        self.update_all_btn = make_button("Update all", suggested=True, row_suffix=True)
        self.update_all_btn.connect("clicked", self._on_update_all)
        update_all_row.add_suffix(self.update_all_btn)
        maintenance.add(update_all_row)

        bootstrap_row = Adw.ActionRow(title="Install runtime and update signatures")
        bootstrap_row.set_subtitle(
            "Private runtime, virus signatures, and pack maintenance",
        )
        self.bootstrap_btn = make_button("Run", suggested=True, row_suffix=True)
        self.bootstrap_btn.connect("clicked", self._on_runtime_bootstrap)
        bootstrap_row.add_suffix(self.bootstrap_btn)
        maintenance.add(bootstrap_row)

        maint_only_row = Adw.ActionRow(title="Maintenance only")
        maint_only_row.set_subtitle(
            "Signatures and baselines without reinstalling the runtime "
            "(may include rkhunter propupd)",
        )
        self.maintenance_only_btn = make_button("Run", row_suffix=True)
        self.maintenance_only_btn.connect("clicked", self._on_maintenance_only)
        maint_only_row.add_suffix(self.maintenance_only_btn)
        maintenance.add(maint_only_row)

        post_update_row = Adw.ActionRow(title="Post-update maintenance")
        post_update_row.set_subtitle(
            "Run maintenance after OS package updates (rkhunter propupd, etc.)",
        )
        self.post_update_btn = make_button("Run", row_suffix=True)
        self.post_update_btn.connect("clicked", self._on_post_update)
        post_update_row.add_suffix(self.post_update_btn)
        maintenance.add(post_update_row)

        rkh_update_row = Adw.ActionRow(title="Update rkhunter data")
        rkh_update_row.set_subtitle(
            "Refresh rkhunter data files (rkhunter --update), not ClamAV signatures",
        )
        self.rkh_update_btn = make_button("Update", row_suffix=True)
        self.rkh_update_btn.connect("clicked", self._on_rkh_update)
        rkh_update_row.add_suffix(self.rkh_update_btn)
        maintenance.add(rkh_update_row)

        rkh_propupd_row = Adw.ActionRow(title="Refresh rkhunter baseline")
        rkh_propupd_row.set_subtitle(
            "Rewrite the property baseline (rkhunter --propupd). "
            "Never run on a system you suspect is compromised.",
        )
        self.rkh_propupd_btn = make_button("Update baseline", row_suffix=True)
        self.rkh_propupd_btn.connect("clicked", self._on_rkh_propupd)
        rkh_propupd_row.add_suffix(self.rkh_propupd_btn)
        maintenance.add(rkh_propupd_row)

        self.maintenance_status_row = Adw.ActionRow(title="Last run")
        self.maintenance_status_row.set_subtitle("No maintenance run yet")
        self.maintenance_status_row.set_sensitive(False)
        maintenance.add(self.maintenance_status_row)

        setup_group = Adw.PreferencesGroup(title="Setup")
        setup_row = Adw.ActionRow(title="First-time setup")
        setup_row.set_subtitle("Re-run the guided setup wizard")
        setup_btn = make_button("Run setup wizard", row_suffix=True)
        setup_btn.connect("clicked", self._on_setup_wizard)
        setup_row.add_suffix(setup_btn)
        setup_group.add(setup_row)

        page.add(maintenance)
        page.add(setup_group)
        self._add_section_page("maintenance", page)

    def _reload_security_packs(self) -> None:
        def load() -> dict[str, Any]:
            return {
                "packs": self.client.doctor(),
                "runtime": self.client.runtime_status(),
            }

        def done(data: dict[str, Any]) -> bool:
            packs_raw = data.get("packs")
            packs = packs_raw if isinstance(packs_raw, list) else []
            runtime_raw = data.get("runtime")
            runtime = runtime_raw if isinstance(runtime_raw, dict) else {}
            self.pack_list.set_packs(list(packs), runtime=runtime)
            refresh_clamonacc_subtitle(self.client, self.clamonacc_row)
            return False

        run_in_thread(load, done, lambda _m: False)

    def _on_runtime_bootstrap(self, *_args: object) -> None:
        self.maintenance_status_row.set_subtitle("Running full bootstrap…")
        self.maintenance_only_btn.set_sensitive(False)

        def on_complete(steps: list[dict[str, Any]]) -> None:
            ok_count = sum(1 for s in steps if s.get("ok"))
            self.maintenance_status_row.set_subtitle(
                f"Full bootstrap finished ({ok_count}/{len(steps)} steps OK)",
            )
            self.maintenance_only_btn.set_sensitive(True)
            self._reload_security_packs()

        def on_error(message: str) -> None:
            self.maintenance_status_row.set_subtitle(f"Bootstrap failed: {message}")
            self.maintenance_only_btn.set_sensitive(True)

        bootstrap_runtime_from_gui(
            self.client,
            window=self._window,
            on_status=self._set_status,
            on_complete=on_complete,
            on_error=on_error,
            update_signatures=True,
            run_maintenance=True,
            progress_button=self.bootstrap_btn,
            progress_verb="Installing",
        )

    def _on_maintenance_only(self, *_args: object) -> None:
        idle = self.maintenance_only_btn.get_label() or "Run"
        self.maintenance_status_row.set_subtitle("Running maintenance…")
        self.bootstrap_btn.set_sensitive(False)

        def worker(report: Callable[[int], None]) -> list[dict[str, object]]:
            _ = report
            result = self.client.maintenance_bootstrap(skip_lynis=True)
            return list(result) if isinstance(result, list) else []

        def done(steps: list[dict[str, object]]) -> None:
            ok_count = sum(1 for s in steps if s.get("ok"))
            self.maintenance_status_row.set_subtitle(
                f"Maintenance finished ({ok_count}/{len(steps)} steps OK)",
            )
            self.bootstrap_btn.set_sensitive(True)
            self._reload_security_packs()

        def fail(message: str) -> None:
            self.maintenance_status_row.set_subtitle(f"Maintenance failed: {message}")
            self.bootstrap_btn.set_sensitive(True)

        run_progress_button(
            self.maintenance_only_btn,
            worker,
            busy_verb="Running",
            idle_label=idle,
            on_success=done,
            on_error=fail,
        )

    def _on_rkh_update(self, *_args: object) -> None:
        self.rkh_update_btn.set_sensitive(False)
        self.maintenance_status_row.set_subtitle("Updating rkhunter data…")

        def done(result: dict[str, Any]) -> bool:
            self.rkh_update_btn.set_sensitive(True)
            msg = result.get("message", "Update finished")
            self.maintenance_status_row.set_subtitle("rkhunter data update finished")
            show_command_dialog(self._window, heading="rkhunter update", body=str(msg))
            return False

        def fail(message: str) -> bool:
            self.rkh_update_btn.set_sensitive(True)
            self.maintenance_status_row.set_subtitle(f"rkhunter update failed: {message}")
            return False

        run_in_thread(self.client.rkhunter_update, done, fail)

    def _on_rkh_propupd(self, *_args: object) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self._window,
            heading="Update rkhunter baseline?",
            body=(
                "Only run propupd on trusted systems. "
                "Never update the baseline on a system you suspect is compromised."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("confirm", "Update baseline")
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_propupd_confirmed)
        dialog.present()

    def _on_propupd_confirmed(self, dialog: Adw.MessageDialog, response: str) -> None:
        _ = dialog
        if response != "confirm":
            return
        self.rkh_propupd_btn.set_sensitive(False)
        self.maintenance_status_row.set_subtitle("Refreshing rkhunter baseline…")

        def done(result: dict[str, Any]) -> bool:
            self.rkh_propupd_btn.set_sensitive(True)
            msg = result.get("message", "propupd finished")
            self.maintenance_status_row.set_subtitle("rkhunter baseline refresh finished")
            show_command_dialog(self._window, heading="rkhunter propupd", body=str(msg))
            return False

        def fail(message: str) -> bool:
            self.rkh_propupd_btn.set_sensitive(True)
            self.maintenance_status_row.set_subtitle(f"rkhunter propupd failed: {message}")
            return False

        run_in_thread(self.client.rkhunter_propupd, done, fail)

    def _on_setup_wizard(self, *_args: object) -> None:
        if self._on_setup_wizard_cb:
            self._on_setup_wizard_cb()

    def _on_news_refresh(self, *_args: object) -> None:
        def done(_: dict[str, Any]) -> bool:
            self._set_status("Security news refreshed")
            if self._on_security_news_changed:
                self._on_security_news_changed()
            return False

        run_in_thread(lambda: request_news_refresh(self.client), done, self._apply_error)

    def _on_update_all(self, *_args: object) -> None:
        self.update_all_btn.set_sensitive(False)
        self._set_status("Running Update all…")

        def done(result: dict[str, Any]) -> bool:
            self.update_all_btn.set_sensitive(True)
            raw_steps = result.get("steps")
            steps: list[Any] = list(raw_steps) if isinstance(raw_steps, list) else []
            ok_count = sum(1 for s in steps if isinstance(s, dict) and s.get("ok"))
            msg = str(result.get("message") or f"Update all finished ({ok_count}/{len(steps)} OK)")
            self._set_status(msg)
            if self._on_updates_changed:
                self._on_updates_changed()
            self._reload_security_packs()
            return False

        def fail(message: str) -> bool:
            self.update_all_btn.set_sensitive(True)
            self._set_status(f"Update all failed: {message}")
            if self._on_updates_changed:
                self._on_updates_changed()
            return False

        run_in_thread(lambda: request_updates_apply(self.client), done, fail)

    def _on_post_update(self, *_args: object) -> None:
        self.post_update_btn.set_sensitive(False)
        self.maintenance_status_row.set_subtitle("Running post-update maintenance…")

        def worker() -> list[dict[str, object]]:
            return self.client.maintenance_post_update()

        def done(steps: list[dict[str, object]]) -> bool:
            self.post_update_btn.set_sensitive(True)
            ok_count = sum(1 for s in steps if s.get("ok"))
            self.maintenance_status_row.set_subtitle(
                f"Post-update finished ({ok_count}/{len(steps)} steps OK)",
            )
            self._reload_security_packs()
            return False

        def fail(message: str) -> bool:
            self.post_update_btn.set_sensitive(True)
            self.maintenance_status_row.set_subtitle(f"Post-update failed: {message}")
            return False

        run_in_thread(worker, done, fail)

    def _build_host_audit_section(self) -> None:
        page = Adw.PreferencesPage()

        host = Adw.PreferencesGroup(
            title="Host security",
            description="Limited firewall / fail2ban controls (full DSL remains CLI).",
        )
        self.firewall_row = Adw.ActionRow(title="Firewall")
        self.firewall_row.set_subtitle("Checking…")
        host.add(self.firewall_row)

        unban_row = Adw.EntryRow(title="fail2ban unban IP")
        unban_row.set_show_apply_button(True)
        unban_row.connect("apply", self._on_fail2ban_unban)
        host.add(unban_row)
        page.add(host)

        audit = Adw.PreferencesGroup(
            title="Audit trail",
            description="Recent privileged and sensitive operations.",
        )
        self.audit_status_row = Adw.ActionRow(title="Recent entries")
        self.audit_status_row.set_subtitle("Loading…")
        refresh_btn = make_button("Refresh", row_suffix=True)
        refresh_btn.connect("clicked", lambda *_: self._refresh_audit())
        self.audit_status_row.add_suffix(refresh_btn)
        audit.add(self.audit_status_row)
        self._audit_detail_rows: list[Adw.ActionRow] = []
        self._audit_group = audit
        page.add(audit)

        self._add_section_page("host_audit", page)

    def _refresh_audit(self) -> None:
        def worker() -> list[dict[str, Any]]:
            return request_audit_list(self.client, limit=8)

        def done(entries: list[dict[str, Any]]) -> bool:
            for row in self._audit_detail_rows:
                self._audit_group.remove(row)
            self._audit_detail_rows.clear()
            if not entries:
                self.audit_status_row.set_subtitle("No audit entries yet")
                return False
            self.audit_status_row.set_subtitle(f"Showing {len(entries)} recent entries")
            for entry in entries[:5]:
                row = Adw.ActionRow(
                    title=str(entry.get("action") or entry.get("kind") or "event"),
                    subtitle=str(entry.get("message") or entry.get("target") or "")[:120],
                )
                self._audit_group.add(row)
                self._audit_detail_rows.append(row)
            return False

        run_in_thread(worker, done, lambda _m: False)

    def _refresh_host_security(self) -> None:
        def worker() -> dict[str, Any]:
            return request_firewall_status(self.client)

        def done(status: dict[str, Any]) -> bool:
            active = status.get("active") or status.get("backend") or "unknown"
            self.firewall_row.set_subtitle(f"Backend: {active}")
            return False

        run_in_thread(worker, done, lambda _m: False)

    def _on_fail2ban_unban(self, row: Adw.EntryRow, *_args: object) -> None:
        ip = row.get_text().strip()
        if not ip:
            return

        def worker() -> dict[str, Any]:
            return request_fail2ban_unban(self.client, ip)

        def done(result: dict[str, Any]) -> bool:
            if result.get("ok"):
                self._set_status(f"Unbanned {ip}")
                row.set_text("")
            else:
                show_command_dialog(
                    self._window,
                    heading="fail2ban unban failed",
                    body=str(result.get("message") or "failed"),
                    copy_text=f"oyst-cli fail2ban unban {ip}",
                )
            return False

        run_in_thread(worker, done, self._apply_error)
