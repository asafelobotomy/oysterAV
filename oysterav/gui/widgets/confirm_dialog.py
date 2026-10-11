"""Reusable destructive-action confirmation dialog (Adw.AlertDialog)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gtk  # noqa: E402


def confirm_destructive(
    window: Gtk.Window | None,
    *,
    heading: str,
    body: str,
    confirm_label: str,
    on_confirm: Callable[[], None],
) -> Any:
    """Ask before a destructive action; run ``on_confirm`` only on confirm.

    Body text is plain (no Pango markup), so paths are shown literally.
    Falls back to ``Adw.MessageDialog`` on libadwaita < 1.5.
    """
    alert_cls = getattr(Adw, "AlertDialog", None)
    if alert_cls is not None:
        dialog = alert_cls(heading=heading, body=body)
    else:  # pragma: no cover — old libadwaita
        dialog = Adw.MessageDialog(transient_for=window, heading=heading, body=body)
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", confirm_label)
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: object, response: str) -> None:
        if response == "confirm":
            on_confirm()

    dialog.connect("response", on_response)
    if alert_cls is not None:
        dialog.present(window)
    else:  # pragma: no cover
        dialog.present()
    return dialog
