"""Scheduling Settings section widget builders."""

from __future__ import annotations

from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.widgets.common import bind_string_combo_row, make_button
from oysterav.gui.widgets.settings_const import (
    FREQUENCY_LABELS,
    QUARANTINE_LABELS,
    SCHED_BACKEND_LABELS,
    SCHEDULE_PROFILE_LABELS,
    WEEKDAY_LABELS,
)
from oysterav.gui.widgets.settings_schedule_apply import (
    on_sched_backend_saved,
    on_sched_calendar_saved,
    on_sched_enabled_saved,
    on_sched_frequency_saved,
    on_sched_packs_saved,
    on_sched_paths_saved,
    on_sched_persistent_saved,
    on_sched_profile_saved,
    on_sched_quarantine_saved,
    on_sched_time_saved,
    on_sched_weekday_saved,
)

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def build_schedule_group(page: SettingsPage) -> None:
    prefs = Adw.PreferencesPage()
    schedule = Adw.PreferencesGroup(title="Scheduling")
    schedule.set_description(
        "Configure when and what the systemd user timer scans. "
        "Changes save automatically and update the timer.",
    )

    page.schedule_status_row = Adw.ActionRow(title="Timer status")
    page.schedule_status_row.set_subtitle("Loading…")
    schedule.add(page.schedule_status_row)

    page.sched_enabled_row = Adw.SwitchRow(title="Enable scheduled scan")
    page.sched_enabled_row.set_subtitle("Enable or disable the systemd user timer")
    page.sched_enabled_row.connect(
        "notify::active",
        lambda *a: on_sched_enabled_saved(page, *a),
    )
    schedule.add(page.sched_enabled_row)

    page.sched_profile_row = Adw.ComboRow(title="Scan profile")
    page.sched_profile_row.set_subtitle("Preset packs and paths (custom needs packs)")
    bind_string_combo_row(page.sched_profile_row, SCHEDULE_PROFILE_LABELS)
    page.sched_profile_row.connect(
        "notify::selected",
        lambda *a: on_sched_profile_saved(page, *a),
    )
    schedule.add(page.sched_profile_row)

    page.sched_frequency_row = Adw.ComboRow(title="Frequency")
    page.sched_frequency_row.set_subtitle("How often the user timer fires")
    bind_string_combo_row(page.sched_frequency_row, FREQUENCY_LABELS)
    page.sched_frequency_row.connect(
        "notify::selected",
        lambda *a: on_sched_frequency_saved(page, *a),
    )
    schedule.add(page.sched_frequency_row)

    page.sched_time_row = Adw.EntryRow(title="Time (HH:MM)")
    page.sched_time_row.set_tooltip_text("Local time for daily and weekly schedules")
    page.sched_time_row.set_show_apply_button(True)
    page.sched_time_row.connect("apply", lambda *a: on_sched_time_saved(page, *a))
    schedule.add(page.sched_time_row)

    page.sched_weekday_row = Adw.ComboRow(title="Weekday")
    page.sched_weekday_row.set_subtitle("Used when frequency is weekly")
    bind_string_combo_row(page.sched_weekday_row, WEEKDAY_LABELS)
    page.sched_weekday_row.connect(
        "notify::selected",
        lambda *a: on_sched_weekday_saved(page, *a),
    )
    schedule.add(page.sched_weekday_row)

    page.sched_calendar_row = Adw.EntryRow(title="Custom OnCalendar")
    page.sched_calendar_row.set_tooltip_text(
        "Required when frequency is Custom. Example: *-*-* 03:30:00. "
        "Press the row checkmark to save.",
    )
    page.sched_calendar_row.set_show_apply_button(True)
    page.sched_calendar_row.connect(
        "apply",
        lambda *a: on_sched_calendar_saved(page, *a),
    )
    schedule.add(page.sched_calendar_row)

    page.sched_packs_row = Adw.EntryRow(title="Packs override")
    page.sched_packs_row.set_tooltip_text(
        "Comma-separated packs; empty uses the profile default. Press the row checkmark to save.",
    )
    page.sched_packs_row.set_show_apply_button(True)
    page.sched_packs_row.connect("apply", lambda *a: on_sched_packs_saved(page, *a))
    schedule.add(page.sched_packs_row)

    page.sched_paths_row = Adw.EntryRow(title="Paths override")
    page.sched_paths_row.set_tooltip_text(
        "Comma-separated paths; empty uses the profile default. Press the row checkmark to save.",
    )
    page.sched_paths_row.set_show_apply_button(True)
    page.sched_paths_row.connect("apply", lambda *a: on_sched_paths_saved(page, *a))
    schedule.add(page.sched_paths_row)

    page.sched_quarantine_row = Adw.ComboRow(title="Quarantine")
    page.sched_quarantine_row.set_subtitle(
        "Timer override — Auto follows General auto-quarantine",
    )
    bind_string_combo_row(page.sched_quarantine_row, QUARANTINE_LABELS)
    page.sched_quarantine_row.connect(
        "notify::selected",
        lambda *a: on_sched_quarantine_saved(page, *a),
    )
    schedule.add(page.sched_quarantine_row)

    page.sched_backend_row = Adw.ComboRow(title="Scan backend")
    page.sched_backend_row.set_subtitle(
        "Timer override — Inherit follows General scan backend",
    )
    bind_string_combo_row(page.sched_backend_row, SCHED_BACKEND_LABELS)
    page.sched_backend_row.connect(
        "notify::selected",
        lambda *a: on_sched_backend_saved(page, *a),
    )
    schedule.add(page.sched_backend_row)

    page.sched_persistent_row = Adw.SwitchRow(title="Catch up missed runs")
    page.sched_persistent_row.set_subtitle(
        "Run missed scans after boot or login (systemd Persistent=true)",
    )
    page.sched_persistent_row.connect(
        "notify::active",
        lambda *a: on_sched_persistent_saved(page, *a),
    )
    schedule.add(page.sched_persistent_row)

    run_row = Adw.ActionRow(title="Run scheduled scan now")
    run_row.set_subtitle(
        "Runs once with the current saved schedule (does not change the timer)",
    )
    page._schedule_run_btn = make_button("Run now", suggested=True, row_suffix=True)
    page._schedule_run_btn.connect("clicked", page._on_schedule_run_now)
    run_row.add_suffix(page._schedule_run_btn)
    schedule.add(run_row)

    prefs.add(schedule)
    page._add_section_page("scheduling", prefs)
