"""Copy text with wl-copy (wl-clipboard).

On Wayland a GTK clipboard value only lives while the window that set it keeps its focus and
stays open, and a dialog that closes on the same click often loses it. `wl-copy` serves the text
from its own background process, so the GUI uses it when it is installed (see
oysterav/gui/clipboard.py).
"""

from __future__ import annotations

import logging
import shutil
import subprocess

_logger = logging.getLogger("oyst.clipboard")


def wl_copy(text: str) -> bool:
    """Put `text` on the Wayland clipboard; False when wl-copy is missing or fails."""
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
