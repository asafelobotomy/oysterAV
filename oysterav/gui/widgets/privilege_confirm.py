"""Confirm dialog before privilege concert actions."""

from __future__ import annotations

from collections.abc import Callable

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.privilege import PrivilegePlan, preflight_body


def confirm_privilege_plan(
    window: Gtk.Window | None,
    plan: PrivilegePlan,
    *,
    on_continue: Callable[[], None],
    continue_label: str = "Continue",
) -> None:
    """Show inform-then-auth dialog; call on_continue only when user confirms."""
    if not plan.needs_elevation:
        on_continue()
        return
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading=plan.title,
        body=preflight_body(plan),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("continue", continue_label)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("continue", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "continue":
            on_continue()

    dialog.connect("response", on_response)
    dialog.present()


__all__ = ["confirm_privilege_plan"]
