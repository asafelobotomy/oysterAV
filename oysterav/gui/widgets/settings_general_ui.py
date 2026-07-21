"""General Settings section builders and save handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oyst_core.security_news import DEFAULT_SOURCE_IDS, NEWS_SOURCES, normalize_max_age_days
from oyst_core.ui_theme import DEFAULT_UI_THEME
from oysterav.gui.rpc_actions import request_news_refresh
from oysterav.gui.theme import apply_theme
from oysterav.gui.widgets import settings_schedule_ui
from oysterav.gui.widgets.clamonacc_ui import refresh_clamonacc_subtitle
from oysterav.gui.widgets.common import bind_string_combo_row, make_button, run_in_thread
from oysterav.gui.widgets.schedule_ui import format_timer_status
from oysterav.gui.widgets.settings_const import (
    BACKEND_OPTIONS,
    NEWS_MAX_AGE_LABELS,
    NEWS_MAX_AGE_OPTIONS,
    SCHEDULE_PROFILE_LABELS,
    SCHEDULE_PROFILE_OPTIONS,
    THEME_LABELS,
    THEME_OPTIONS,
)

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def build_general_section(page: SettingsPage) -> None:
    prefs = Adw.PreferencesPage()
    general = Adw.PreferencesGroup(title="General")

    page.backend_status_row = Adw.ActionRow(title="oyst-cli backend")
    page.backend_status_row.set_subtitle("Checking connection…")
    page.backend_status_row.set_sensitive(False)
    general.add(page.backend_status_row)

    page.security_news_row = Adw.SwitchRow(title="Security news ticker")
    page.security_news_row.set_subtitle(
        "Scroll selected advisories in the status bar (severity-prioritized)",
    )
    page.security_news_row.connect(
        "notify::active",
        lambda *a: on_security_news_saved(page, *a),
    )
    general.add(page.security_news_row)

    page.news_max_age_row = Adw.ComboRow(title="News freshness")
    page.news_max_age_row.set_subtitle(
        "Only show advisories published within this window (default: 14 days)",
    )
    bind_string_combo_row(page.news_max_age_row, NEWS_MAX_AGE_LABELS)
    page.news_max_age_row.connect(
        "notify::selected",
        lambda *a: on_news_max_age_saved(page, *a),
    )
    general.add(page.news_max_age_row)

    news_refresh_row = Adw.ActionRow(title="Refresh security news")
    news_refresh_row.set_subtitle("Force-refresh selected advisory feeds now")
    news_refresh_btn = make_button("Refresh", row_suffix=True)
    news_refresh_btn.connect("clicked", lambda *a: on_news_refresh(page, *a))
    news_refresh_row.add_suffix(news_refresh_btn)
    general.add(news_refresh_row)

    prefs.add(general)

    sources_group = Adw.PreferencesGroup(
        title="News sources",
        description="Enable one or more feeds. Highest-severity headlines appear first.",
    )
    page._news_source_rows = {}
    _source_subtitles = {
        "arch": "Arch Linux Security Advisories (ASA)",
        "ubuntu": "Ubuntu Security Notices (USN)",
        "debian": "Debian Security Advisories (DSA)",
        "gentoo": "Gentoo Linux Security Advisories (GLSA)",
        "fedora": "Fedora Bodhi security updates",
        "opensuse": "openSUSE / SUSE security-announce list",
        "oss-security": "Open Source Security mailing list (seclists)",
    }
    for sid, src in NEWS_SOURCES.items():
        row = Adw.SwitchRow(title=src.label)
        row.set_subtitle(_source_subtitles.get(sid, src.url))
        row.connect("notify::active", lambda *a: on_news_sources_saved(page, *a))
        sources_group.add(row)
        page._news_source_rows[sid] = row
    prefs.add(sources_group)

    general_scan = Adw.PreferencesGroup(title="Scan defaults")

    page.auto_quarantine_row = Adw.SwitchRow(title="Auto-quarantine threats")
    page.auto_quarantine_row.set_subtitle(
        "Default after scans; Scheduling can override for the timer",
    )
    page.auto_quarantine_row.connect(
        "notify::active",
        lambda *a: on_auto_quarantine_saved(page, *a),
    )
    general_scan.add(page.auto_quarantine_row)

    page.profile_row = Adw.ComboRow(title="Default scan profile")
    page.profile_row.set_subtitle(
        "Default for the Scan tab and `oyst-cli scan` when --profile is omitted",
    )
    bind_string_combo_row(page.profile_row, SCHEDULE_PROFILE_LABELS)
    page.profile_row.connect("notify::selected", lambda *a: on_profile_saved(page, *a))
    general_scan.add(page.profile_row)

    page.backend_row = Adw.ComboRow(title="Scan backend")
    page.backend_row.set_subtitle(
        "Default for manual scans (prefer clamd); Scheduling can inherit this",
    )
    bind_string_combo_row(page.backend_row, BACKEND_OPTIONS)
    page.backend_row.connect("notify::selected", lambda *a: on_backend_saved(page, *a))
    general_scan.add(page.backend_row)

    appearance = Adw.PreferencesGroup(title="Appearance & desktop")

    page.theme_row = Adw.ComboRow(title="Theme")
    page.theme_row.set_subtitle("Application colors (default: Gruvbox Dark Hard)")
    bind_string_combo_row(page.theme_row, THEME_LABELS)
    page.theme_row.connect("notify::selected", lambda *a: on_theme_saved(page, *a))
    appearance.add(page.theme_row)

    page.run_at_startup_row = Adw.SwitchRow(title="Run at startup")
    page.run_at_startup_row.set_subtitle("Launch oysterAV when you log in (XDG autostart)")
    page.run_at_startup_row.connect(
        "notify::active",
        lambda *a: on_run_at_startup_saved(page, *a),
    )
    appearance.add(page.run_at_startup_row)

    page.start_minimized_row = Adw.SwitchRow(title="Start minimized")
    page.start_minimized_row.set_subtitle(
        "Hide the window on launch (requires a working tray)",
    )
    page.start_minimized_row.connect(
        "notify::active",
        lambda *a: on_start_minimized_saved(page, *a),
    )
    appearance.add(page.start_minimized_row)

    page.minimize_to_tray_row = Adw.SwitchRow(title="Minimize to tray on close")
    page.minimize_to_tray_row.set_subtitle(
        "Close hides oysterAV in the tray instead of quitting",
    )
    page.minimize_to_tray_row.connect(
        "notify::active",
        lambda *a: on_minimize_to_tray_saved(page, *a),
    )
    appearance.add(page.minimize_to_tray_row)

    prefs.add(general_scan)
    prefs.add(appearance)
    page._add_section_page("general", prefs)


def sync_news_source_sensitivity(page: SettingsPage) -> None:
    enabled = bool(page.security_news_row.get_active())
    page.news_max_age_row.set_sensitive(enabled)
    for row in page._news_source_rows.values():
        row.set_sensitive(enabled)


def on_security_news_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    if page._loading:
        return
    page._save("ui.security_news", "true" if row.get_active() else "false")
    sync_news_source_sensitivity(page)
    if page._on_security_news_changed:
        page._on_security_news_changed()


def on_news_max_age_saved(page: SettingsPage, *_args: object) -> None:
    if page._loading:
        return
    value = page._selected_option(page.news_max_age_row, NEWS_MAX_AGE_OPTIONS)
    if not value:
        return
    page._save("ui.security_news_max_age_days", value)
    if page._on_security_news_changed:
        page._on_security_news_changed()


def on_news_sources_saved(page: SettingsPage, *_args: object) -> None:
    if page._loading:
        return
    selected = [sid for sid, row in page._news_source_rows.items() if row.get_active()]
    if not selected:
        # Keep at least one source — re-enable catalog defaults.
        defaults = list(DEFAULT_SOURCE_IDS)
        page._loading = True
        for sid, row in page._news_source_rows.items():
            row.set_active(sid in defaults)
        page._loading = False
        selected = defaults
        page._set_status("At least one news source is required")

    def done(_: object) -> bool:
        page._set_status("Saved security news sources")
        if page._on_security_news_changed:
            # Force refresh so the ticker matches the new selection.
            on_news_refresh(page)
        return False

    run_in_thread(
        lambda: page.client.config_set("ui.security_news_sources", ",".join(selected)),
        done,
        page._apply_error,
    )


def on_auto_quarantine_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    val = "true" if row.get_active() else "false"
    page._save("quarantine.auto", val)


def on_profile_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.profile_row, SCHEDULE_PROFILE_OPTIONS)
    if value:
        page._save("scan.profile", value)


def on_backend_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.backend_row, BACKEND_OPTIONS)
    if value:
        page._save("scan.backend", value)


def on_theme_saved(page: SettingsPage, *_args: object) -> None:
    if page._loading:
        return
    theme_id = page._selected_option(page.theme_row, THEME_OPTIONS)
    if theme_id:
        page._save("ui.theme", theme_id)
        apply_theme(theme_id)


def on_run_at_startup_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    page._save("ui.run_at_startup", "true" if row.get_active() else "false")


def on_start_minimized_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    page._save("ui.start_minimized", "true" if row.get_active() else "false")


def on_minimize_to_tray_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    page._save("ui.minimize_to_tray", "true" if row.get_active() else "false")


def on_news_refresh(page: SettingsPage, *_args: object) -> None:
    def done(_: dict[str, Any]) -> bool:
        page._set_status("Security news refreshed")
        if page._on_security_news_changed:
            page._on_security_news_changed()
        return False

    run_in_thread(lambda: request_news_refresh(page.client), done, page._apply_error)


def apply_settings_data(page: SettingsPage, data: dict[str, Any]) -> bool:
    page._loading = True
    config = data.get("config")
    if not isinstance(config, dict):
        page.backend_status_row.set_subtitle("Not connected — invalid config response")
        page._loading = False
        return False

    page.backend_status_row.set_subtitle("Connected")

    runtime_status = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    page.pack_list.set_packs(list(data.get("packs", [])), runtime=runtime_status)

    quarantine = config.get("quarantine", {})
    page.auto_quarantine_row.set_active(bool(quarantine.get("auto")))

    scan_cfg = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
    profile = str(scan_cfg.get("profile", "quick"))
    if profile in SCHEDULE_PROFILE_OPTIONS:
        page.profile_row.set_selected(SCHEDULE_PROFILE_OPTIONS.index(profile))

    backend = scan_cfg.get("backend", "auto")
    if backend in BACKEND_OPTIONS:
        page.backend_row.set_selected(BACKEND_OPTIONS.index(backend))

    ui_raw = config.get("ui")
    ui = ui_raw if isinstance(ui_raw, dict) else {}
    page.security_news_row.set_active(bool(ui.get("security_news", True)))
    age_key = str(normalize_max_age_days(ui.get("security_news_max_age_days", 14)))
    page.news_max_age_row.set_selected(NEWS_MAX_AGE_OPTIONS.index(age_key))
    raw_sources = ui.get("security_news_sources")
    enabled_sources = (
        {str(s) for s in raw_sources} if isinstance(raw_sources, list) else set(DEFAULT_SOURCE_IDS)
    )
    for sid, row in page._news_source_rows.items():
        row.set_active(sid in enabled_sources)
    sync_news_source_sensitivity(page)
    theme = str(ui.get("theme", DEFAULT_UI_THEME))
    if theme in THEME_OPTIONS:
        page.theme_row.set_selected(THEME_OPTIONS.index(theme))
    else:
        page.theme_row.set_selected(THEME_OPTIONS.index(DEFAULT_UI_THEME))
    page.run_at_startup_row.set_active(bool(ui.get("run_at_startup")))
    page.start_minimized_row.set_active(bool(ui.get("start_minimized")))
    page.minimize_to_tray_row.set_active(bool(ui.get("minimize_to_tray")))
    desktop_raw = data.get("desktop")
    tray = desktop_raw if isinstance(desktop_raw, dict) else {}
    tray_info_raw = tray.get("tray")
    tray_info = tray_info_raw if isinstance(tray_info_raw, dict) else {}
    if not tray_info.get("available", True):
        hint = str(tray_info.get("hint") or "Tray host unavailable")
        page.start_minimized_row.set_subtitle(f"Requires a working tray — {hint}")
        page.minimize_to_tray_row.set_subtitle(
            f"Close hides to tray when available — {hint}",
        )
    else:
        page.start_minimized_row.set_subtitle(
            "Hide the window on launch (requires a working tray)",
        )
        page.minimize_to_tray_row.set_subtitle(
            "Close hides oysterAV in the tray instead of quitting",
        )

    clamonacc = config.get("clamonacc", {})
    page.clamonacc_row.set_active(bool(clamonacc.get("enabled")))
    refresh_clamonacc_subtitle(page.client, page.clamonacc_row)
    page._populate_clamonacc_paths(clamonacc.get("paths", []))

    schedule_status = data.get("schedule", {})
    sched_cfg = config.get("schedule", {})
    if not isinstance(sched_cfg, dict) and isinstance(schedule_status, dict):
        raw = schedule_status.get("config")
        sched_cfg = raw if isinstance(raw, dict) else {}
    if isinstance(sched_cfg, dict):
        settings_schedule_ui.apply_schedule_config(page, sched_cfg)
    if isinstance(schedule_status, dict):
        page.schedule_status_row.set_subtitle(format_timer_status(schedule_status))

    page._loading = False
    return False
