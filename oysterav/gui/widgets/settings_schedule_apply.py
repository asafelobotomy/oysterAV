"""Scheduling Settings apply, validation, and save handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib  # noqa: E402

from oyst_core.models import PROFILE_PACKS, PROFILE_PATHS, ScanProfile
from oyst_core.schedule_util import parse_schedule_time
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.schedule_ui import show_schedule_result
from oysterav.gui.widgets.settings_const import (
    FREQUENCY_OPTIONS,
    QUARANTINE_OPTIONS,
    SCHED_BACKEND_OPTIONS,
    SCHEDULE_APPLY_DEBOUNCE_MS,
    SCHEDULE_PROFILE_OPTIONS,
    WEEKDAY_OPTIONS,
)

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def apply_schedule_config(page: SettingsPage, cfg: dict[str, Any]) -> None:
    page.sched_enabled_row.set_active(bool(cfg.get("enabled")))

    profile = str(cfg.get("profile", "quick"))
    if profile in SCHEDULE_PROFILE_OPTIONS:
        page.sched_profile_row.set_selected(SCHEDULE_PROFILE_OPTIONS.index(profile))

    freq = str(cfg.get("frequency", "daily"))
    if freq in FREQUENCY_OPTIONS:
        page.sched_frequency_row.set_selected(FREQUENCY_OPTIONS.index(freq))

    page.sched_time_row.set_text(str(cfg.get("time", "02:00")))

    weekday = str(cfg.get("weekday", "mon")).lower()
    if weekday in WEEKDAY_OPTIONS:
        page.sched_weekday_row.set_selected(WEEKDAY_OPTIONS.index(weekday))

    page.sched_calendar_row.set_text(str(cfg.get("on_calendar", "")))
    packs = cfg.get("packs") or []
    paths = cfg.get("paths") or []
    page.sched_packs_row.set_text(",".join(str(p) for p in packs) if packs else "")
    page.sched_paths_row.set_text(",".join(str(p) for p in paths) if paths else "")
    update_schedule_override_hints(page, profile)

    quarantine = str(cfg.get("quarantine", "auto"))
    if quarantine in QUARANTINE_OPTIONS:
        page.sched_quarantine_row.set_selected(QUARANTINE_OPTIONS.index(quarantine))

    backend = str(cfg.get("backend", "inherit"))
    if backend in SCHED_BACKEND_OPTIONS:
        page.sched_backend_row.set_selected(SCHED_BACKEND_OPTIONS.index(backend))

    page.sched_persistent_row.set_active(bool(cfg.get("persistent", True)))
    update_schedule_row_sensitivity(page, freq)
    if freq == "custom":
        seed_custom_on_calendar_if_empty(page)


def update_schedule_override_hints(page: SettingsPage, profile: str) -> None:
    try:
        sp = ScanProfile(profile)
    except ValueError:
        sp = ScanProfile.QUICK
    pack_default = ", ".join(PROFILE_PACKS.get(sp, [])) or "(none)"
    path_default = ", ".join(PROFILE_PATHS.get(sp, [])) or "(none)"
    page.sched_packs_row.set_title(f"Packs override (default: {pack_default})")
    page.sched_paths_row.set_title(f"Paths override (default: {path_default})")


def update_schedule_row_sensitivity(page: SettingsPage, frequency: str) -> None:
    page.sched_time_row.set_sensitive(frequency in ("daily", "weekly"))
    page.sched_weekday_row.set_sensitive(frequency == "weekly")
    page.sched_calendar_row.set_sensitive(frequency == "custom")
    if frequency == "custom":
        page.sched_calendar_row.set_title("Custom OnCalendar (required)")
    else:
        page.sched_calendar_row.set_title("Custom OnCalendar")


def seed_custom_on_calendar_if_empty(page: SettingsPage) -> None:
    if page.sched_calendar_row.get_text().strip():
        return
    at_time = page.sched_time_row.get_text().strip() or "02:00"
    try:
        hour_s, minute_s = at_time.split(":", 1)
        hour, minute = int(hour_s), int(minute_s)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
        seeded = f"*-*-* {hour:02d}:{minute:02d}:00"
    except ValueError:
        seeded = "*-*-* 02:00:00"
    page.sched_calendar_row.set_text(seeded)
    if not page._loading:
        page._save("schedule.on_calendar", seeded)


def schedule_validation_error(page: SettingsPage) -> str | None:
    frequency = page._selected_option(page.sched_frequency_row, FREQUENCY_OPTIONS) or "daily"
    profile = page._selected_option(page.sched_profile_row, SCHEDULE_PROFILE_OPTIONS) or "quick"
    on_calendar = page.sched_calendar_row.get_text().strip()
    packs = page.sched_packs_row.get_text().strip()
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
    if frequency in ("daily", "weekly"):
        at_time = page.sched_time_row.get_text().strip()
        try:
            parse_schedule_time(at_time)
        except ValueError:
            return (
                "Time must be HH:MM (24-hour), for example 02:00 or 14:30.\n\n"
                f"Current value: {at_time or '(empty)'}"
            )
    return None


def show_schedule_validation_dialog(page: SettingsPage, body: str) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Cannot update schedule timer",
        body=body,
    )
    dialog.add_response("ok", "OK")
    dialog.set_default_response("ok")
    dialog.set_close_response("ok")
    dialog.present()


def queue_timer_apply(page: SettingsPage) -> None:
    if page._schedule_apply_timeout:
        GLib.source_remove(page._schedule_apply_timeout)
        page._schedule_apply_timeout = 0
    page._schedule_apply_timeout = GLib.timeout_add(
        SCHEDULE_APPLY_DEBOUNCE_MS,
        lambda: run_timer_apply(page),
    )


def run_timer_apply(page: SettingsPage) -> bool:
    page._schedule_apply_timeout = 0
    if page._loading:
        return False
    validation = schedule_validation_error(page)
    if validation:
        show_schedule_validation_dialog(page, validation)
        return False
    if page._schedule_applying:
        queue_timer_apply(page)
        return False

    page._schedule_applying = True
    page._schedule_run_btn.set_sensitive(False)

    def worker() -> dict[str, Any]:
        return page.client.schedule_apply(smoke_test=True)

    def on_complete(result: dict[str, Any]) -> bool:
        page._schedule_applying = False
        page._schedule_run_btn.set_sensitive(True)
        if not result.get("ok"):
            show_command_dialog(
                page._window,
                heading="Could not update schedule timer",
                body=str(result.get("message", "Schedule apply failed")),
                copy_text=str(result.get("enable_hint") or "") or None,
            )
            page.refresh()
            return False

        message = str(result.get("message", "Schedule timer updated"))
        page._set_status(message)
        page.refresh()

        linger = result.get("linger") if isinstance(result.get("linger"), dict) else {}
        advisory = result.get("linger_advisory")
        if (
            result.get("enabled")
            and advisory
            and isinstance(linger, dict)
            and not linger.get("linger", True)
            and not page._linger_prompted
        ):
            page._linger_prompted = True
            show_schedule_result(
                page._window,
                result,
                on_status=page._set_status,
                client=page.client,
            )
        return False

    def on_error(message: str) -> bool:
        page._schedule_applying = False
        page._schedule_run_btn.set_sensitive(True)
        return page._apply_error(message)

    run_in_thread(worker, on_complete, on_error)
    return False


def on_sched_enabled_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    page._save("schedule.enabled", "true" if row.get_active() else "false")


def on_sched_profile_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.sched_profile_row, SCHEDULE_PROFILE_OPTIONS)
    if value:
        page._save("schedule.profile", value)
        update_schedule_override_hints(page, value)


def on_sched_frequency_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.sched_frequency_row, FREQUENCY_OPTIONS)
    if value:
        page._save("schedule.frequency", value)
        update_schedule_row_sensitivity(page, value)
        if value == "custom":
            seed_custom_on_calendar_if_empty(page)


def on_sched_time_saved(page: SettingsPage, row: Adw.EntryRow, *_args: object) -> None:
    text = row.get_text().strip()
    if not text:
        return
    try:
        hour, minute = parse_schedule_time(text)
    except ValueError:
        show_schedule_validation_dialog(
            page,
            f"Time must be HH:MM (24-hour), for example 02:00 or 14:30.\n\nCurrent value: {text}",
        )
        page._set_status("Invalid schedule.time — expected HH:MM")
        return
    page._save("schedule.time", f"{hour:02d}:{minute:02d}")


def on_sched_weekday_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.sched_weekday_row, WEEKDAY_OPTIONS)
    if value:
        page._save("schedule.weekday", value)


def on_sched_calendar_saved(page: SettingsPage, row: Adw.EntryRow, *_args: object) -> None:
    page._save("schedule.on_calendar", row.get_text().strip())


def on_sched_packs_saved(page: SettingsPage, row: Adw.EntryRow, *_args: object) -> None:
    page._save("schedule.packs", row.get_text().strip())


def on_sched_paths_saved(page: SettingsPage, row: Adw.EntryRow, *_args: object) -> None:
    page._save("schedule.paths", row.get_text().strip())


def on_sched_quarantine_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.sched_quarantine_row, QUARANTINE_OPTIONS)
    if value:
        page._save("schedule.quarantine", value)


def on_sched_backend_saved(page: SettingsPage, *_args: object) -> None:
    value = page._selected_option(page.sched_backend_row, SCHED_BACKEND_OPTIONS)
    if value:
        page._save("schedule.backend", value)


def on_sched_persistent_saved(page: SettingsPage, row: Adw.SwitchRow, *_args: object) -> None:
    page._save("schedule.persistent", "true" if row.get_active() else "false")
