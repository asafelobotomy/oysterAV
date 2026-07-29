#!/usr/bin/env python3
"""Capture oysterAV GUI tab screenshots for README / AppStream.

Runs a short-lived GTK session, switches ViewStack tabs, and writes PNGs under
docs/assets/screenshots/ via Gtk.WidgetPaintable + the window Gsk renderer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import GLib, Gtk  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets" / "screenshots"

TABS: tuple[tuple[str, str], ...] = (
    ("dashboard", "dashboard"),
    ("scan", "scan"),
    ("shield", "shield"),
    ("reports", "reports"),
    ("quarantine", "quarantine"),
    ("settings", "settings"),
)


def _capture_window(win: Gtk.Window, dest: Path) -> None:
    native = win.get_native()
    if native is None:
        raise RuntimeError("window has no native")
    renderer = native.get_renderer()
    if renderer is None:
        raise RuntimeError("window has no renderer")
    width = max(win.get_width(), 1)
    height = max(win.get_height(), 1)
    paintable = Gtk.WidgetPaintable.new(win)
    snap = Gtk.Snapshot()
    paintable.snapshot(snap, float(width), float(height))
    node = snap.to_node()
    if node is None:
        raise RuntimeError(f"empty render node for {dest.name}")
    texture = renderer.render_texture(node, None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    texture.save_to_png(str(dest))
    print(f"Wrote {dest} ({width}x{height})", flush=True)


def main() -> int:
    sys.path.insert(0, str(ROOT))

    import oysterav.gui.widgets.setup_wizard as wiz_mod
    from oysterav.gui.app import OysterApp

    # Avoid first-run wizard overlay in marketing shots.
    wiz_mod.should_show_wizard = lambda *_a, **_k: False  # type: ignore[assignment]

    class CaptureApp(OysterApp):
        def do_activate(self) -> None:  # noqa: N802 — GObject override
            super().do_activate()
            win = self._window
            if win is None:
                raise RuntimeError("OysterWindow not created")
            win.set_default_size(960, 700)
            win.present()
            state = {"i": 0}

            def after_settle(filename: str) -> bool:
                _capture_window(win, OUT / f"{filename}.png")
                GLib.timeout_add(300, step)
                return False

            def step() -> bool:
                idx = int(state["i"])
                if idx >= len(TABS):
                    self.quit()
                    return False
                filename, child = TABS[idx]
                state["i"] = idx + 1
                win.stack.set_visible_child_name(child)
                # Trigger page refresh when available (dashboard / settings / etc.).
                page = {
                    "dashboard": win.dashboard,
                    "scan": win.scan,
                    "shield": win.shield,
                    "reports": win.reports,
                    "quarantine": win.quarantine,
                    "settings": win.settings,
                }.get(child)
                if page is not None and hasattr(page, "refresh"):
                    try:
                        page.refresh()
                    except Exception:  # noqa: BLE001
                        pass
                settle_ms = 2200 if filename == "dashboard" else 1100
                GLib.timeout_add(settle_ms, after_settle, filename)
                return False

            GLib.timeout_add(2500, step)

    app = CaptureApp(start_minimized=False)
    return app.run([])


if __name__ == "__main__":
    raise SystemExit(main())
