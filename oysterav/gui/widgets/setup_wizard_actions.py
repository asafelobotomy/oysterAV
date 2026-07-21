"""Doctor / install / bootstrap / finish actions for the setup wizard."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.runtime_ui import (
    bootstrap_runtime_from_gui,
    format_runtime_status_line,
)
from oysterav.gui.widgets.schedule_ui import show_schedule_result
from oysterav.gui.widgets.setup_wizard_text import format_check_summary

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def run_doctor(wizard: SetupWizard) -> None:
    wizard._doctor_running = True
    wizard._doctor_done = False
    wizard.check_spinner.start()
    wizard.check_label.set_text(format_check_summary(wizard._setup, running=True))
    wizard._update_nav()

    def worker() -> dict[str, Any]:
        packs = wizard.client.doctor()
        setup = wizard.client.setup_status()
        try:
            runtime = wizard.client.runtime_status()
        except RuntimeError:
            runtime = {}
        return {"packs": packs, "setup": setup, "runtime": runtime}

    run_in_thread(
        worker,
        lambda data: apply_doctor(wizard, data),
        lambda message: apply_doctor_error(wizard, message),
    )


def apply_doctor(wizard: SetupWizard, data: dict[str, Any]) -> bool:
    wizard._packs = list(data.get("packs", []))
    wizard._setup = dict(data.get("setup", {}))
    runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
    wizard.pack_list.set_packs(wizard._packs, runtime=runtime)
    wizard.runtime_status_label.set_text(
        format_runtime_status_line(runtime) if runtime else "Mode: — · Disk: —",
    )
    wizard._doctor_running = False
    wizard._doctor_done = True
    wizard.check_spinner.stop()
    wizard.check_label.set_text(format_check_summary(wizard._setup))
    wizard.welcome_status.set_text(format_check_summary(wizard._setup))
    wizard._refresh_install_gate()
    wizard._refresh_ready_summary()
    wizard._update_nav()
    return False


def apply_doctor_error(wizard: SetupWizard, message: str) -> bool:
    wizard._doctor_running = False
    wizard._doctor_done = True
    wizard.check_spinner.stop()
    wizard.check_label.set_text(f"Doctor failed: {message}")
    wizard.welcome_status.set_text(f"Doctor failed: {message}")
    wizard._update_nav()
    return False


def on_packs_changed(wizard: SetupWizard) -> None:
    wizard._packs = wizard.pack_list.get_packs()
    try:
        wizard._setup = wizard.client.setup_status()
    except RuntimeError as exc:
        wizard._set_status(f"Could not refresh setup status: {exc}")
    wizard._refresh_install_gate()
    wizard.check_label.set_text(format_check_summary(wizard._setup))
    wizard.welcome_status.set_text(format_check_summary(wizard._setup))
    wizard._refresh_ready_summary()
    wizard._update_nav()
    wizard._emit_changed()


def on_install_skip(wizard: SetupWizard, *_args: object) -> None:
    wizard._install_skipped = True
    wizard.install_warning.set_revealed(False)
    try:
        wizard.client.config_set("setup.skipped_steps", "required_packs")
        wizard._setup = wizard.client.setup_status()
    except RuntimeError as exc:
        wizard._set_status(f"Could not record skipped packs: {exc}")
    wizard._refresh_ready_summary()
    wizard._update_nav()


def set_bootstrap_busy(wizard: SetupWizard, busy: bool) -> None:
    wizard._bootstrap_busy = busy
    wizard.bootstrap_primary_btn.set_sensitive(not busy)
    wizard.bootstrap_secondary_btn.set_sensitive(not busy)
    wizard._update_nav()


def on_full_bootstrap(wizard: SetupWizard, *_args: object) -> None:
    if wizard._bootstrap_busy:
        return
    set_bootstrap_busy(wizard, True)
    wizard.bootstrap_label.set_text(
        "Installing runtime, updating signatures, running bootstrap…",
    )

    def on_complete(steps: list[dict[str, Any]]) -> None:
        ok_count = sum(1 for r in steps if r.get("ok"))
        wizard.bootstrap_label.set_text(
            f"Full bootstrap finished ({ok_count}/{len(steps)} steps OK).",
        )
        wizard._bootstrap_ran = ok_count > 0
        set_bootstrap_busy(wizard, False)
        run_doctor(wizard)
        wizard._emit_changed()

    def on_error(message: str) -> None:
        wizard.bootstrap_label.set_text(f"Bootstrap failed: {message}")
        set_bootstrap_busy(wizard, False)

    bootstrap_runtime_from_gui(
        wizard.client,
        window=wizard._parent_window,
        parent=wizard.dialog,
        on_status=wizard._set_status,
        on_complete=on_complete,
        on_error=on_error,
        update_signatures=True,
        run_maintenance=True,
        progress_button=wizard.bootstrap_primary_btn,
        progress_verb="Installing",
    )


def on_bootstrap_only(wizard: SetupWizard, *_args: object) -> None:
    if wizard._bootstrap_busy:
        return
    set_bootstrap_busy(wizard, True)
    wizard.bootstrap_label.set_text("Running maintenance bootstrap…")

    def done(steps: list[dict[str, object]]) -> bool:
        ok_count = sum(1 for s in steps if s.get("ok"))
        wizard.bootstrap_label.set_text(
            f"Maintenance finished ({ok_count}/{len(steps)} steps OK).",
        )
        wizard._bootstrap_ran = ok_count > 0
        set_bootstrap_busy(wizard, False)
        run_doctor(wizard)
        wizard._emit_changed()
        return False

    def on_error(message: str) -> bool:
        set_bootstrap_busy(wizard, False)
        wizard.bootstrap_label.set_text(f"Maintenance failed: {message}")
        return False

    run_in_thread(
        lambda: wizard.client.maintenance_bootstrap(skip_lynis=True),
        done,
        on_error,
    )


def on_schedule_install(wizard: SetupWizard, *_args: object) -> None:
    profile, frequency, at_time = wizard._selected_schedule()

    wizard.schedule_label.set_text("Installing scheduled scan timer…")
    wizard.schedule_btn.set_sensitive(False)

    def worker() -> dict[str, Any]:
        wizard.client.config_set("schedule.profile", profile)
        wizard.client.config_set("schedule.frequency", frequency)
        wizard.client.config_set("schedule.time", at_time)
        wizard.client.config_set("schedule.enabled", "true")
        return wizard.client.schedule_apply(smoke_test=True)

    def on_complete(result: dict[str, Any]) -> bool:
        wizard.schedule_btn.set_sensitive(True)
        show_schedule_result(
            wizard._parent_window,
            result,
            parent=wizard.dialog,
            on_status=wizard._set_status,
            client=wizard.client,
            on_complete=lambda _r: None,
        )

        def apply_status(status: dict[str, Any]) -> bool:
            wizard._apply_schedule_ui(status)
            wizard._emit_changed()
            return False

        def apply_fallback(_message: str) -> bool:
            wizard._apply_schedule_ui(result)
            wizard._emit_changed()
            return False

        run_in_thread(wizard.client.schedule_status, apply_status, apply_fallback)
        return False

    def on_error(message: str) -> bool:
        wizard.schedule_btn.set_sensitive(True)
        wizard.schedule_label.set_text(f"Schedule failed: {message}")
        return False

    run_in_thread(worker, on_complete, on_error)


def finish_gaps(wizard: SetupWizard) -> list[str]:
    gaps: list[str] = []
    if wizard._full_mode and not wizard._bootstrap_ran:
        gaps.append("Runtime bootstrap / signatures were not run")
    if not wizard._schedule_installed:
        gaps.append("Scheduled scan timer was not installed")
    if not wizard._harden_ran:
        gaps.append("Host hardenings were not applied")
    return gaps


def finish_setup(wizard: SetupWizard, *, mark_complete: bool = True) -> None:
    if wizard._dismissed or wizard._finish_pending:
        return
    if mark_complete:
        gaps = finish_gaps(wizard)
        if gaps:
            confirm_finish_with_gaps(wizard, gaps)
            return
    complete_finish(wizard, mark_complete=mark_complete)


def confirm_finish_with_gaps(wizard: SetupWizard, gaps: list[str]) -> None:
    wizard._finish_pending = True
    wizard._update_nav()
    body = "You can finish now and configure these later in Settings:\n\n" + "\n".join(
        f"• {g}" for g in gaps
    )
    dialog = Adw.MessageDialog(
        transient_for=wizard.dialog,
        heading="Finish setup with optional steps pending?",
        body=body,
    )
    dialog.add_response("back", "Go back")
    dialog.add_response("finish", "Finish anyway")
    dialog.set_response_appearance("finish", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("back")
    dialog.set_close_response("back")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        wizard._finish_pending = False
        wizard._update_nav()
        if response == "finish":
            complete_finish(wizard, mark_complete=True)

    dialog.connect("response", on_response)
    dialog.present()


def complete_finish(wizard: SetupWizard, *, mark_complete: bool = True) -> None:
    if wizard._dismissed:
        return
    wizard._dismissed = True
    if mark_complete:
        try:
            wizard.client.setup_run(
                skip_packs=True,
                skip_schedule=True,
                skip_bootstrap=True,
                skip_harden=True,
                enable_firewall=False,
                auto_quarantine=wizard.auto_quarantine.get_active(),
                mark_complete=True,
            )
        except RuntimeError as exc:
            wizard._set_status(f"Could not mark setup complete: {exc}")
            show_command_dialog(
                wizard.dialog,
                heading="Setup incomplete",
                body=f"Could not mark setup complete:\n{exc}",
                copy_text=("oyst-cli setup run --skip-packs --skip-schedule --skip-bootstrap"),
            )
            wizard._dismissed = False
            return
    wizard.dialog.destroy()
    if wizard._on_complete:
        wizard._on_complete()
    elif wizard._on_changed:
        wizard._on_changed()
