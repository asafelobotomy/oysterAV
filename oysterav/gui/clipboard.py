"""Copy text to the clipboard for the GTK app: wl-copy first, GDK as the fallback."""

from __future__ import annotations

import logging

from oyst_core.clipboard import wl_copy

_logger = logging.getLogger("oyst.gui.clipboard")


def _gdk_copy(text: str) -> bool:
    try:
        import gi

        gi.require_version("Gdk", "4.0")
        from gi.repository import Gdk

        display = Gdk.Display.get_default()
        if display is None:
            return False
        display.get_clipboard().set(Gdk.ContentProvider.new_for_value(text))
    except (ImportError, ValueError) as exc:
        _logger.warning("GDK clipboard failed: %s", exc)
        return False
    return True


def copy_to_clipboard(text: str) -> bool:
    """Put `text` on the clipboard; False when neither wl-copy nor GDK could."""
    return wl_copy(text) or _gdk_copy(text)
