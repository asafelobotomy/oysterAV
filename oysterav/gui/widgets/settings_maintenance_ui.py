"""Maintenance Settings section builders and handlers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.widgets.bulk_checklist import make_bulk_expander
from oysterav.gui.widgets.clamonacc_ui import refresh_clamonacc_subtitle
from oysterav.gui.widgets.common import make_button, run_in_thread, show_command_dialog
from oysterav.gui.widgets.progress_button import run_progress_button
from oysterav.gui.widgets.runtime_ui import bootstrap_runtime_from_gui
from oysterav.gui.widgets.settings_maintenance_update import on_update_all

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def build_maintenance_group(page: SettingsPage) -> None:
    prefs = Adw.PreferencesPage()
    maintenance = Adw.PreferencesGroup(title="Maintenance")
    maintenance.set_description(
        "Install or refresh the private runtime, virus signatures, and baselines. "
        "Maintenance only may refresh the rkhunter baseline without a separate confirm.",
    )

    update_all_row = Adw.ActionRow(title="Update all")
    update_all_row.set_subtitle(
        "Upgrade related packages when needed, refresh definitions, then baselines",
    )
    page.update_all_btn = make_button("Update all", suggested=True, row_suffix=True)
    page.update_all_btn.connect("clicked", lambda *a: on_update_all(page, *a))
    update_all_row.add_suffix(page.update_all_btn)
    maintenance.add(update_all_row)

    expander = make_bulk_expander(
        "Steps included in Update all",
        subtitle="Run individual steps, or use Update all above",
        expanded=True,
    )

    page.maintenance_only_btn = make_button("Run", row_suffix=True)
    page.maintenance_only_btn.connect(
        "clicked",
        lambda *a: on_maintenance_only(page, *a),
    )
    maint_row = Adw.ActionRow(title="Maintenance only")
    maint_row.set_subtitle(
        "Signatures and baselines without reinstalling the runtime "
        "(may refresh the rkhunter file baseline)",
    )
    maint_row.add_suffix(page.maintenance_only_btn)
    expander.add_row(maint_row)

    page.post_update_btn = make_button("Run", row_suffix=True)
    page.post_update_btn.connect("clicked", lambda *a: on_post_update(page, *a))
    post_row = Adw.ActionRow(title="Post-update maintenance")
    post_row.set_subtitle("After OS package updates (refresh rkhunter baseline, etc.)")
    post_row.add_suffix(page.post_update_btn)
    expander.add_row(post_row)

    page.rkh_update_btn = make_button("Update", row_suffix=True)
    page.rkh_update_btn.connect("clicked", lambda *a: on_rkh_update(page, *a))
    rkh_u = Adw.ActionRow(title="Update rkhunter data")
    rkh_u.set_subtitle("Refresh rkhunter data files (not ClamAV signatures)")
    rkh_u.add_suffix(page.rkh_update_btn)
    expander.add_row(rkh_u)

    page.rkh_propupd_btn = make_button("Update baseline", row_suffix=True)
    page.rkh_propupd_btn.connect("clicked", lambda *a: on_rkh_propupd(page, *a))
    rkh_p = Adw.ActionRow(title="Refresh rkhunter baseline")
    rkh_p.set_subtitle(
        "Updates the trusted file property baseline. "
        "Never run on a system you suspect is compromised.",
    )
    rkh_p.add_suffix(page.rkh_propupd_btn)
    expander.add_row(rkh_p)
    maintenance.add(expander)

    bootstrap_row = Adw.ActionRow(title="Install runtime and update signatures")
    bootstrap_row.set_subtitle(
        "Private runtime, virus signatures, and pack maintenance (not part of Update all)",
    )
    page.bootstrap_btn = make_button("Run", suggested=True, row_suffix=True)
    page.bootstrap_btn.connect("clicked", lambda *a: on_runtime_bootstrap(page, *a))
    bootstrap_row.add_suffix(page.bootstrap_btn)
    maintenance.add(bootstrap_row)

    page.maintenance_status_row = Adw.ActionRow(title="Last run")
    page.maintenance_status_row.set_subtitle("No maintenance run yet")
    page.maintenance_status_row.set_sensitive(False)
    maintenance.add(page.maintenance_status_row)

    setup_group = Adw.PreferencesGroup(title="Setup")
    setup_row = Adw.ActionRow(title="First-time setup")
    setup_row.set_subtitle("Re-run the guided setup wizard")
    setup_btn = make_button("Run setup wizard", row_suffix=True)
    setup_btn.connect("clicked", lambda *a: on_setup_wizard(page, *a))
    setup_row.add_suffix(setup_btn)
    setup_group.add(setup_row)

    prefs.add(maintenance)
    prefs.add(setup_group)
    page._add_section_page("maintenance", prefs)


def reload_security_packs(page: SettingsPage) -> None:
    def load() -> dict[str, Any]:
        return {
            "packs": page.client.doctor(),
            "runtime": page.client.runtime_status(),
        }

    def done(data: dict[str, Any]) -> bool:
        packs_raw = data.get("packs")
        packs = packs_raw if isinstance(packs_raw, list) else []
        runtime_raw = data.get("runtime")
        runtime = runtime_raw if isinstance(runtime_raw, dict) else {}
        page.pack_list.set_packs(list(packs), runtime=runtime)
        refresh_clamonacc_subtitle(page.client, page.clamonacc_row)
        return False

    run_in_thread(load, done, lambda _m: False)


def on_runtime_bootstrap(page: SettingsPage, *_args: object) -> None:
    page.maintenance_status_row.set_subtitle("Running full bootstrap…")
    page.maintenance_only_btn.set_sensitive(False)

    def on_complete(steps: list[dict[str, Any]]) -> None:
        ok_count = sum(1 for s in steps if s.get("ok"))
        page.maintenance_status_row.set_subtitle(
            f"Full bootstrap finished ({ok_count}/{len(steps)} steps OK)",
        )
        page.maintenance_only_btn.set_sensitive(True)
        reload_security_packs(page)

    def on_error(message: str) -> None:
        page.maintenance_status_row.set_subtitle(f"Bootstrap failed: {message}")
        page.maintenance_only_btn.set_sensitive(True)

    bootstrap_runtime_from_gui(
        page.client,
        window=page._window,
        on_status=page._set_status,
        on_complete=on_complete,
        on_error=on_error,
        update_signatures=True,
        run_maintenance=True,
        progress_button=page.bootstrap_btn,
        progress_verb="Installing",
    )


def on_maintenance_only(page: SettingsPage, *_args: object) -> None:
    idle = page.maintenance_only_btn.get_label() or "Run"
    page.maintenance_status_row.set_subtitle("Running maintenance…")
    page.bootstrap_btn.set_sensitive(False)

    def worker(report: Callable[[int], None]) -> list[dict[str, object]]:
        _ = report
        result = page.client.maintenance_bootstrap(skip_lynis=True)
        return list(result) if isinstance(result, list) else []

    def done(steps: list[dict[str, object]]) -> None:
        ok_count = sum(1 for s in steps if s.get("ok"))
        page.maintenance_status_row.set_subtitle(
            f"Maintenance finished ({ok_count}/{len(steps)} steps OK)",
        )
        page.bootstrap_btn.set_sensitive(True)
        reload_security_packs(page)

    def fail(message: str) -> None:
        page.maintenance_status_row.set_subtitle(f"Maintenance failed: {message}")
        page.bootstrap_btn.set_sensitive(True)

    run_progress_button(
        page.maintenance_only_btn,
        worker,
        busy_verb="Running",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


def on_rkh_update(page: SettingsPage, *_args: object) -> None:
    page.rkh_update_btn.set_sensitive(False)
    page.maintenance_status_row.set_subtitle("Updating rkhunter data…")

    def done(result: dict[str, Any]) -> bool:
        page.rkh_update_btn.set_sensitive(True)
        msg = result.get("message", "Update finished")
        page.maintenance_status_row.set_subtitle("rkhunter data update finished")
        show_command_dialog(page._window, heading="rkhunter update", body=str(msg))
        return False

    def fail(message: str) -> bool:
        page.rkh_update_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"rkhunter update failed: {message}")
        return False

    run_in_thread(page.client.rkhunter_update, done, fail)


def on_rkh_propupd(page: SettingsPage, *_args: object) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Update rkhunter baseline?",
        body=(
            "Only refresh the file baseline on trusted systems. "
            "Never update the baseline on a system you suspect is compromised."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Update baseline")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.connect("response", lambda d, r: on_propupd_confirmed(page, d, r))
    dialog.present()


def on_propupd_confirmed(
    page: SettingsPage,
    dialog: Adw.MessageDialog,
    response: str,
) -> None:
    _ = dialog
    if response != "confirm":
        return
    page.rkh_propupd_btn.set_sensitive(False)
    page.maintenance_status_row.set_subtitle("Refreshing rkhunter baseline…")

    def done(result: dict[str, Any]) -> bool:
        page.rkh_propupd_btn.set_sensitive(True)
        msg = result.get("message", "Baseline refresh finished")
        page.maintenance_status_row.set_subtitle("rkhunter baseline refresh finished")
        show_command_dialog(page._window, heading="Refresh rkhunter baseline", body=str(msg))
        return False

    def fail(message: str) -> bool:
        page.rkh_propupd_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"Baseline refresh failed: {message}")
        return False

    run_in_thread(page.client.rkhunter_propupd, done, fail)


def on_setup_wizard(page: SettingsPage, *_args: object) -> None:
    if page._on_setup_wizard_cb:
        page._on_setup_wizard_cb()


def on_post_update(page: SettingsPage, *_args: object) -> None:
    page.post_update_btn.set_sensitive(False)
    page.maintenance_status_row.set_subtitle("Running post-update maintenance…")

    def worker() -> list[dict[str, object]]:
        return page.client.maintenance_post_update()

    def done(steps: list[dict[str, object]]) -> bool:
        page.post_update_btn.set_sensitive(True)
        ok_count = sum(1 for s in steps if s.get("ok"))
        page.maintenance_status_row.set_subtitle(
            f"Post-update finished ({ok_count}/{len(steps)} steps OK)",
        )
        reload_security_packs(page)
        return False

    def fail(message: str) -> bool:
        page.post_update_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"Post-update failed: {message}")
        return False

    run_in_thread(worker, done, fail)
