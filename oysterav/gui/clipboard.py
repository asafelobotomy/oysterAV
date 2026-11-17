"""Copy text to the clipboard for the GTK app.

On Wayland a GTK clipboard value only lives while the window that set it keeps its focus and
stays open, and a dialog that closes on the same click often loses it, so the button looked
broken. `wl-copy` (wl-clipboard) serves the text from its own background process, so it is used
when it is installed; GDK is the fallback.
"""

from __future__ import annotations

import logging
import shutil
import subprocess

_logger = logging.getLogger("oyst.gui.clipboard")


def _wl_copy(text: str) -> bool:
    exe = shutil.which("wl-copy")
    if exe is None:
        return False
    try:
        proc = subprocess.Popen(  # noqa: S603
            [exe],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        assert proc.stdin is not None
        proc.stdin.write(text.encode("utf-8"))
        proc.stdin.close()  # wl-copy then forks into the background to serve the text
        return proc.wait(timeout=5) == 0
    except (OSError, subprocess.SubprocessError) as exc:
        _logger.warning("wl-copy failed: %s", exc)
        return False


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
    return _wl_copy(text) or _gdk_copy(text)
