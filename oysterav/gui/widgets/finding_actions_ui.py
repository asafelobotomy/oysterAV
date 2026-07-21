"""Finding action buttons and confirm dialogs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from oyst_core.packs.rkhunter_resolve import plan_resolve
from oyst_core.privilege import PrivilegePlan, build_rkhunter_resolve_plan
from oysterav.gui.finding_present import DisplayFinding
from oysterav.gui.rpc_actions import (
    request_quarantine_add,
    request_rkhunter_propupd,
    request_rkhunter_resolve,
)
from oysterav.gui.widgets.common import make_button, run_in_thread
from oysterav.gui.widgets.privilege_confirm import confirm_privilege_plan


def action_button(label: str, callback: Callable[[], None]) -> Gtk.Button:
    btn = make_button(label)
    btn.set_halign(Gtk.Align.START)
    btn.connect("clicked", lambda *_: callback())
    return btn


def disabled_label_button(label: str) -> Gtk.Button:
    btn = make_button(label)
    btn.set_halign(Gtk.Align.START)
    btn.set_sensitive(False)
    return btn


def copy_text(text: str, on_status: Callable[[str], None] | None) -> None:
    display = Gdk.Display.get_default()
    if display is None:
        return
    display.get_clipboard().set(Gdk.ContentProvider.new_for_value(text))
    if on_status:
        on_status("Copied to clipboard")


def confirm_quarantine(
    window: Gtk.Window | None,
    client: Any,
    row: DisplayFinding,
    on_status: Callable[[str], None] | None,
    *,
    job_id: str | None,
    on_refresh: Callable[[], None] | None,
) -> None:
    path = row.path
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Quarantine file?",
        body=f"Move this file into the oysterAV quarantine vault:\n{path}",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Quarantine")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.SUGGESTED)

    threat = row.threat_name
    pack = row.pack
    message = row.message

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def worker() -> dict[str, Any]:
            return request_quarantine_add(
                client,
                path,
                threat,
                job_id=job_id,
                pack=pack,
                message=message,
            )

        def done(_: dict[str, Any]) -> bool:
            row.raw["quarantined"] = True
            if on_status:
                on_status(f"Quarantined {path}")
            if on_refresh:
                on_refresh()
            return False

        def failed(err: str) -> bool:
            if on_status:
                on_status(f"Quarantine failed: {err}")
            return False

        run_in_thread(worker, done, failed)

    dialog.connect("response", on_response)
    dialog.present()


def confirm_propupd(
    window: Gtk.Window | None,
    client: Any,
    on_status: Callable[[str], None] | None,
) -> None:
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Refresh rkhunter baseline?",
        body=(
            "Only refresh the file baseline on a trusted system. "
            "This rewrites the property database."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Update baseline")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def done(result: dict[str, Any]) -> bool:
            msg = result.get("message", "Baseline refresh finished")
            if on_status:
                on_status(str(msg))
            return False

        def failed(err: str) -> bool:
            if on_status:
                on_status(f"Baseline refresh failed: {err}")
            return False

        run_in_thread(lambda: request_rkhunter_propupd(client), done, failed)

    dialog.connect("response", on_response)
    dialog.present()


def confirm_resolve(
    window: Gtk.Window | None,
    client: Any,
    row: DisplayFinding,
    on_status: Callable[[str], None] | None,
    *,
    job_id: str | None,
    on_refresh: Callable[[], None] | None,
) -> None:
    try:
        resolve_plan = plan_resolve(row.threat_name, path=row.path, message=row.message)
    except ValueError as exc:
        if on_status:
            on_status(f"Resolve unavailable: {exc}")
        return

    priv = build_rkhunter_resolve_plan([(resolve_plan.option, resolve_plan.value)])
    enriched = PrivilegePlan(
        recipe=priv.recipe,
        title=priv.title,
        summary=f"{resolve_plan.explanation}\n\n{priv.summary}",
        argv1=priv.argv1,
        helper_argv=list(priv.helper_argv),
        privileged_steps=list(priv.privileged_steps),
    )

    threat = row.threat_name
    path = row.path
    message = row.message

    def on_continue() -> None:
        def worker() -> dict[str, Any]:
            return request_rkhunter_resolve(
                client,
                threat,
                path=path,
                message=message,
                job_id=job_id,
            )

        def done(result: dict[str, Any]) -> bool:
            if result.get("ok"):
                row.raw["resolved"] = True
                if on_status:
                    on_status(
                        f"Resolved: {result.get('option')}={result.get('value')} "
                        "(re-scan to verify)"
                    )
                if on_refresh:
                    on_refresh()
            elif on_status:
                on_status(f"Resolve failed: {result.get('error') or 'unknown'}")
            return False

        def failed(err: str) -> bool:
            if on_status:
                on_status(f"Resolve failed: {err}")
            return False

        run_in_thread(worker, done, failed)

    confirm_privilege_plan(
        window,
        enriched,
        on_continue=on_continue,
        continue_label="Resolve",
    )
