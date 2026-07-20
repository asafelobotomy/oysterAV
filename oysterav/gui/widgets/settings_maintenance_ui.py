"""Maintenance Settings section builders and handlers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.rpc_actions import request_updates_apply
from oysterav.gui.widgets.clamonacc_ui import refresh_clamonacc_subtitle
from oysterav.gui.widgets.common import make_button, run_in_thread, show_command_dialog
from oysterav.gui.widgets.progress_button import run_progress_button
from oysterav.gui.widgets.runtime_ui import bootstrap_runtime_from_gui

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
        "Check pack/service packages, upgrade when needed, refresh definitions, "
        "then post-update baseline",
    )
    page.update_all_btn = make_button("Update all", suggested=True, row_suffix=True)
    page.update_all_btn.connect("clicked", lambda *a: on_update_all(page, *a))
    update_all_row.add_suffix(page.update_all_btn)
    maintenance.add(update_all_row)

    bootstrap_row = Adw.ActionRow(title="Install runtime and update signatures")
    bootstrap_row.set_subtitle(
        "Private runtime, virus signatures, and pack maintenance",
    )
    page.bootstrap_btn = make_button("Run", suggested=True, row_suffix=True)
    page.bootstrap_btn.connect("clicked", lambda *a: on_runtime_bootstrap(page, *a))
    bootstrap_row.add_suffix(page.bootstrap_btn)
    maintenance.add(bootstrap_row)

    maint_only_row = Adw.ActionRow(title="Maintenance only")
    maint_only_row.set_subtitle(
        "Signatures and baselines without reinstalling the runtime (may include rkhunter propupd)",
    )
    page.maintenance_only_btn = make_button("Run", row_suffix=True)
    page.maintenance_only_btn.connect(
        "clicked",
        lambda *a: on_maintenance_only(page, *a),
    )
    maint_only_row.add_suffix(page.maintenance_only_btn)
    maintenance.add(maint_only_row)

    post_update_row = Adw.ActionRow(title="Post-update maintenance")
    post_update_row.set_subtitle(
        "Run maintenance after OS package updates (rkhunter propupd, etc.)",
    )
    page.post_update_btn = make_button("Run", row_suffix=True)
    page.post_update_btn.connect("clicked", lambda *a: on_post_update(page, *a))
    post_update_row.add_suffix(page.post_update_btn)
    maintenance.add(post_update_row)

    rkh_update_row = Adw.ActionRow(title="Update rkhunter data")
    rkh_update_row.set_subtitle(
        "Refresh rkhunter data files (rkhunter --update), not ClamAV signatures",
    )
    page.rkh_update_btn = make_button("Update", row_suffix=True)
    page.rkh_update_btn.connect("clicked", lambda *a: on_rkh_update(page, *a))
    rkh_update_row.add_suffix(page.rkh_update_btn)
    maintenance.add(rkh_update_row)

    rkh_propupd_row = Adw.ActionRow(title="Refresh rkhunter baseline")
    rkh_propupd_row.set_subtitle(
        "Rewrite the property baseline (rkhunter --propupd). "
        "Never run on a system you suspect is compromised.",
    )
    page.rkh_propupd_btn = make_button("Update baseline", row_suffix=True)
    page.rkh_propupd_btn.connect("clicked", lambda *a: on_rkh_propupd(page, *a))
    rkh_propupd_row.add_suffix(page.rkh_propupd_btn)
    maintenance.add(rkh_propupd_row)

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
            "Only run propupd on trusted systems. "
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
        msg = result.get("message", "propupd finished")
        page.maintenance_status_row.set_subtitle("rkhunter baseline refresh finished")
        show_command_dialog(page._window, heading="rkhunter propupd", body=str(msg))
        return False

    def fail(message: str) -> bool:
        page.rkh_propupd_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"rkhunter propupd failed: {message}")
        return False

    run_in_thread(page.client.rkhunter_propupd, done, fail)


def on_setup_wizard(page: SettingsPage, *_args: object) -> None:
    if page._on_setup_wizard_cb:
        page._on_setup_wizard_cb()


def on_update_all(page: SettingsPage, *_args: object) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Run Update all?",
        body=(
            "This refreshes pack definitions and may run rkhunter --propupd "
            "(updates the file property baseline). Continue?"
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("run", "Update all")
    dialog.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "run":
            return
        page.update_all_btn.set_sensitive(False)
        page.maintenance_status_row.set_subtitle("Running Update all…")
        page._set_status("Running Update all…")

        def done(result: dict[str, Any]) -> bool:
            page.update_all_btn.set_sensitive(True)
            raw_steps = result.get("steps")
            steps: list[Any] = list(raw_steps) if isinstance(raw_steps, list) else []
            ok_count = sum(1 for s in steps if isinstance(s, dict) and s.get("ok"))
            msg = str(
                result.get("message") or f"Update all finished ({ok_count}/{len(steps)} OK)",
            )
            page.maintenance_status_row.set_subtitle(msg)
            page._set_status(msg)
            if page._on_updates_changed:
                page._on_updates_changed()
            reload_security_packs(page)
            return False

        def fail(message: str) -> bool:
            page.update_all_btn.set_sensitive(True)
            page.maintenance_status_row.set_subtitle(f"Update all failed: {message}")
            page._set_status(f"Update all failed: {message}")
            if page._on_updates_changed:
                page._on_updates_changed()
            return False

        run_in_thread(lambda: request_updates_apply(page.client), done, fail)

    dialog.connect("response", on_response)
    dialog.present()


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
