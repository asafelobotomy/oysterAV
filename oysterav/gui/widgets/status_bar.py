"""Shell status bar with operational messages, update alerts, and security-news marquee."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gio", "2.0")

from gi.repository import Gio, GLib, Gtk  # noqa: E402

from oyst_core.security_news import headlines_for_ticker
from oyst_core.updates import format_update_status_line
from oysterav.gui.widgets.common import run_in_thread

_IDLE_STATUSES = frozenset({"", "Ready"})
_MARQUEE_MS = 40
_OVERRIDE_RESTORE_MS = 12_000
_UPDATE_ROTATE_MS = 8_000


class StatusBar(Gtk.Box):
    """Operational status with update alerts (priority) and optional news marquee."""

    def __init__(
        self,
        *,
        load_headlines: Callable[[], dict[str, Any]],
        load_updates: Callable[[], dict[str, Any]],
        news_enabled: Callable[[], bool],
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._load_headlines = load_headlines
        self._load_updates = load_updates
        self._news_enabled = news_enabled
        self._operational = "Ready"
        self._headline_text = ""
        self._news_items: list[dict[str, Any]] = []
        self._updates: list[dict[str, Any]] = []
        self._update_index = 0
        self._marquee_id = 0
        self._restore_id = 0
        self._rotate_id = 0
        self._scroll_pos = 0.0

        self.set_margin_start(12)
        self.set_margin_end(12)
        self.set_margin_top(6)
        self.set_margin_bottom(6)
        self.add_css_class("oyster-status-bar")

        self._op_label = Gtk.Label(label="Ready", xalign=0)
        self._op_label.set_halign(Gtk.Align.START)
        self._op_label.add_css_class("dim-label")
        self.append(self._op_label)

        self._scroll = Gtk.ScrolledWindow()
        self._scroll.set_policy(Gtk.PolicyType.EXTERNAL, Gtk.PolicyType.NEVER)
        self._scroll.set_hexpand(True)
        self._scroll.set_visible(False)
        self._scroll.set_size_request(-1, 22)

        self._news_label = Gtk.Label(label="", xalign=0)
        self._news_label.set_halign(Gtk.Align.START)
        self._news_label.add_css_class("dim-label")
        self._news_label.set_selectable(False)
        click = Gtk.GestureClick()
        click.set_button(1)
        click.connect("released", self._on_news_clicked)
        self._news_label.add_controller(click)
        self._scroll.set_child(self._news_label)
        self.append(self._scroll)

    def set_status(self, text: str) -> None:
        self._operational = text or "Ready"
        self._sync_mode()
        if self._operational not in _IDLE_STATUSES:
            self._schedule_idle_restore()

    def refresh_news(self) -> None:
        if not self._news_enabled():
            self._headline_text = ""
            self._news_items = []
            self._news_label.set_tooltip_text(None)
            self._sync_mode()
            return

        def worker() -> dict[str, Any]:
            return self._load_headlines()

        run_in_thread(worker, self._on_news_loaded, lambda _m: False)

    def refresh_updates(self) -> None:
        def worker() -> dict[str, Any]:
            return self._load_updates()

        run_in_thread(worker, self._on_updates_loaded, lambda _m: False)

    def _on_news_loaded(self, data: dict[str, Any]) -> bool:
        self._headline_text = headlines_for_ticker(data)
        self._scroll_pos = 0.0
        raw_items = data.get("items") if isinstance(data, dict) else None
        items: list[dict[str, Any]] = []
        if isinstance(raw_items, list):
            items = [i for i in raw_items if isinstance(i, dict)]
        self._news_items = items
        self._update_news_tooltip()
        self._sync_mode()
        return False

    def _update_news_tooltip(self) -> None:
        if not self._news_items:
            self._news_label.set_tooltip_text(None)
            return
        top = self._news_items[0]
        title = str(top.get("title") or "").strip()
        published = str(top.get("published") or "").strip()
        source = str(top.get("source") or "").strip()
        lines = [f"{source}: {title}" if source else title]
        if published:
            lines.append(published)
        lines.append("Click to open the top (highest-severity) advisory")
        self._news_label.set_tooltip_text("\n".join(lines))

    def _on_news_clicked(self, *_args: object) -> None:
        if not self._news_items:
            return
        link = str(self._news_items[0].get("link") or "").strip()
        if not link:
            return
        try:
            Gio.AppInfo.launch_default_for_uri(link, None)
        except GLib.Error:
            pass

    def _on_updates_loaded(self, data: dict[str, Any]) -> bool:
        raw = data.get("updates") if isinstance(data, dict) else None
        updates: list[dict[str, Any]] = []
        if isinstance(raw, list):
            updates = [u for u in raw if isinstance(u, dict)]
        self._updates = updates
        self._update_index = 0
        self._sync_mode()
        return False

    def _current_update_text(self) -> str:
        if not self._updates:
            return ""
        idx = self._update_index % len(self._updates)
        return format_update_status_line(self._updates[idx])

    def _schedule_idle_restore(self) -> None:
        if self._restore_id:
            GLib.source_remove(self._restore_id)
            self._restore_id = 0

        def restore() -> bool:
            self._restore_id = 0
            if self._operational not in _IDLE_STATUSES:
                self._operational = "Ready"
                self._sync_mode()
            return False

        self._restore_id = GLib.timeout_add(_OVERRIDE_RESTORE_MS, restore)

    def _sync_mode(self) -> None:
        idle = self._operational in _IDLE_STATUSES
        update_text = self._current_update_text() if idle else ""
        show_update = bool(update_text)
        show_news = idle and not show_update and self._news_enabled() and bool(self._headline_text)

        self._op_label.remove_css_class("dim-label")
        self._op_label.remove_css_class("oyster-update-alert")
        if show_update:
            self._op_label.set_text(update_text)
            self._op_label.add_css_class("oyster-update-alert")
            self._op_label.set_visible(True)
            self._scroll.set_visible(False)
            self._stop_marquee()
            self._start_update_rotate()
            return

        self._stop_update_rotate()
        if show_news:
            self._op_label.set_visible(False)
            self._scroll.set_visible(True)
            self._news_label.set_text(f"{self._headline_text}     ···     {self._headline_text}")
            self._start_marquee()
            return

        self._op_label.add_css_class("dim-label")
        self._op_label.set_text(self._operational)
        self._op_label.set_visible(True)
        self._scroll.set_visible(False)
        self._stop_marquee()

    def _start_update_rotate(self) -> None:
        if self._rotate_id or len(self._updates) <= 1:
            return

        def tick() -> bool:
            if not self._updates or self._operational not in _IDLE_STATUSES:
                self._rotate_id = 0
                return False
            self._update_index = (self._update_index + 1) % len(self._updates)
            self._op_label.set_text(self._current_update_text())
            return True

        self._rotate_id = GLib.timeout_add(_UPDATE_ROTATE_MS, tick)

    def _stop_update_rotate(self) -> None:
        if self._rotate_id:
            GLib.source_remove(self._rotate_id)
            self._rotate_id = 0

    def _start_marquee(self) -> None:
        if self._marquee_id:
            return

        def tick() -> bool:
            if not self._scroll.get_visible():
                self._marquee_id = 0
                return False
            adj = self._scroll.get_hadjustment()
            if adj is None:
                return True
            upper = adj.get_upper()
            page = adj.get_page_size()
            if upper <= page + 1:
                return True
            self._scroll_pos += 1.0
            loop_at = max(1.0, (upper - page) / 2.0)
            if self._scroll_pos >= loop_at:
                self._scroll_pos = 0.0
            adj.set_value(self._scroll_pos)
            return True

        self._marquee_id = GLib.timeout_add(_MARQUEE_MS, tick)

    def _stop_marquee(self) -> None:
        if self._marquee_id:
            GLib.source_remove(self._marquee_id)
            self._marquee_id = 0
