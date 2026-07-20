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
from oysterav.gui.finding_present import DisplayFinding
from oysterav.gui.rpc_actions import (
    request_quarantine_add,
    request_rkhunter_propupd,
    request_rkhunter_resolve,
)
from oysterav.gui.widgets.common import make_button, run_in_thread


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
            "Only run propupd on a trusted system. "
            "This rewrites the property database (rkhunter --propupd)."
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
            msg = result.get("message", "propupd finished")
            if on_status:
                on_status(str(msg))
            return False

        def failed(err: str) -> bool:
            if on_status:
                on_status(f"rkhunter propupd failed: {err}")
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
        plan = plan_resolve(row.threat_name, path=row.path, message=row.message)
    except ValueError as exc:
        if on_status:
            on_status(f"Resolve unavailable: {exc}")
        return

    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Resolve rkhunter finding?",
        body=(
            f"{plan.explanation}\n\n"
            f"Writes {plan.option}={plan.value} to "
            "/etc/rkhunter.d/oysterav-whitelist.conf. "
            "Does not delete files or edit sshd_config. "
            "Re-scan afterward to verify."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Resolve")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.SUGGESTED)

    threat = row.threat_name
    path = row.path
    message = row.message

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

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

    dialog.connect("response", on_response)
    dialog.present()
