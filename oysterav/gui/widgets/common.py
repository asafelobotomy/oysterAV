"""Shared GUI helpers and widgets."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import Adw, Gdk, GLib, Gtk, Pango  # noqa: E402

from oyst_core.health import SIGNATURE_STALE_HOURS
from oyst_core.models import PROFILE_PATHS, ScanProfile


def make_button(
    label: str,
    *,
    suggested: bool = False,
    destructive: bool = False,
    row_suffix: bool = False,
) -> Gtk.Button:
    """Create a consistently sized button (ActionRow-safe when row_suffix=True)."""
    button = Gtk.Button(label=label)
    button.add_css_class("oyster-button")
    if suggested:
        button.add_css_class("suggested-action")
    if destructive:
        button.add_css_class("destructive-action")
    if row_suffix:
        # Without CENTER, Adw.ActionRow stretches the button to the full row height.
        button.set_valign(Gtk.Align.CENTER)
    if hasattr(button, "set_can_shrink"):
        button.set_can_shrink(False)
    child = button.get_child()
    if isinstance(child, Gtk.Label):
        child.set_ellipsize(Pango.EllipsizeMode.NONE)
    return button


_STATUS_CSS_CLASSES = ("success", "warning", "error")


def apply_status_css(widget: Gtk.Widget, css_class: str = "") -> None:
    """Apply a single success/warning/error class (clears the others)."""
    for cls in _STATUS_CSS_CLASSES:
        widget.remove_css_class(cls)
    if css_class in _STATUS_CSS_CLASSES:
        widget.add_css_class(css_class)


def make_status_badge(text: str, css_class: str = "") -> Gtk.Label:
    """Compact themed status badge for ActionRow suffixes / list chrome."""
    badge = Gtk.Label(label=text)
    badge.set_valign(Gtk.Align.CENTER)
    badge.add_css_class("oyster-status-badge")
    apply_status_css(badge, css_class)
    return badge


def make_section_heading(text: str) -> Gtk.Label:
    """Consistent section label used across Reports, Scan, dialogs, wizard."""
    heading = Gtk.Label(label=text, xalign=0)
    heading.add_css_class("heading")
    heading.add_css_class("oyster-section-heading")
    return heading


def _combo_list_factory(*, compact: bool = False) -> Gtk.SignalListItemFactory:
    """Popup factory: full label text + selection checkmark (no ellipsis)."""
    factory = Gtk.SignalListItemFactory()
    icon_px = 14 if compact else 16
    row_spacing = 6 if compact else 8

    def on_setup(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=row_spacing)
        if compact:
            row.set_margin_top(2)
            row.set_margin_bottom(2)
        check = Gtk.Image.new_from_icon_name("object-select-symbolic")
        check.set_pixel_size(icon_px)
        check.set_opacity(0.0)
        label = Gtk.Label(xalign=0.0)
        label.set_halign(Gtk.Align.START)
        label.set_hexpand(True)
        label.set_ellipsize(Pango.EllipsizeMode.NONE)
        label.set_wrap(False)
        if compact:
            label.add_css_class("caption")
        row.append(check)
        row.append(label)
        item.set_child(row)

        def sync_check(*_args: object) -> None:
            check.set_opacity(1.0 if item.get_selected() else 0.0)

        item.connect("notify::selected", sync_check)

    def on_bind(_factory: Gtk.SignalListItemFactory, item: Gtk.ListItem) -> None:
        row = item.get_child()
        if not isinstance(row, Gtk.Box):
            return
        check = row.get_first_child()
        label = check.get_next_sibling() if check is not None else None
        obj = item.get_item()
        text = obj.get_string() if obj is not None else ""
        if isinstance(label, Gtk.Label):
            label.set_label(text)
        if isinstance(check, Gtk.Image):
            check.set_opacity(1.0 if item.get_selected() else 0.0)

    factory.connect("setup", on_setup)
    factory.connect("bind", on_bind)
    return factory


def bind_string_combo_row(
    row: Adw.ComboRow,
    labels: list[str],
    *,
    compact: bool = False,
) -> None:
    """Bind string options so the open menu never truncates labels."""
    row.set_model(Gtk.StringList.new(labels))
    row.set_list_factory(_combo_list_factory(compact=compact))
    row.add_css_class("oyster-combo")
    if compact:
        row.add_css_class("oyster-scan-combo")


def run_in_thread(
    worker: Callable[[], Any],
    on_success: Callable[[Any], Any],
    on_error: Callable[[str], Any],
) -> None:
    def target() -> None:
        try:
            result = worker()
            GLib.idle_add(on_success, result)
        except Exception as exc:  # noqa: BLE001 — GUI boundary
            GLib.idle_add(on_error, str(exc))

    threading.Thread(target=target, daemon=True).start()


def parse_iso(ts: str | datetime | None) -> datetime | None:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def format_relative_time(ts: str | datetime | None) -> str:
    dt = parse_iso(ts)
    if dt is None:
        return "Never"
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "Just now"
    if seconds < 60:
        return "Just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    days = hours // 24
    if days < 30:
        return f"{days}d ago"
    return dt.strftime("%Y-%m-%d")


def format_signature_age(hours: float | None) -> tuple[str, str]:
    if hours is None:
        return ("Unknown", "warning")
    if hours < 24:
        return ("Updated today", "success")
    if hours < SIGNATURE_STALE_HOURS:
        return (f"{int(hours)}h old", "success")
    return (f"Stale ({int(hours)}h)", "warning")


def severity_css_class(severity: str) -> str:
    match severity.lower():
        case "critical" | "high":
            return "error"
        case "medium":
            return "warning"
        case _:
            return "success"


def dialog_parent(window: Gtk.Window | None, parent: Gtk.Window | None) -> Gtk.Window | None:
    return parent or window


def clear_list_box(list_box: Gtk.ListBox) -> None:
    while row := list_box.get_row_at_index(0):
        list_box.remove(row)


def make_scrolled_page(content: Gtk.Widget) -> Gtk.ScrolledWindow:
    scroll = Gtk.ScrolledWindow()
    scroll.set_hexpand(True)
    scroll.set_vexpand(True)
    scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroll.set_child(content)
    return scroll


def default_paths_for_profile(profile: str) -> list[str]:
    try:
        scan_profile = ScanProfile(profile)
    except ValueError:
        scan_profile = ScanProfile.QUICK
    return [str(p) for p in PROFILE_PATHS.get(scan_profile, ["~"])]


def show_command_dialog(
    window: Gtk.Window | None,
    *,
    heading: str,
    body: str,
    copy_text: str | None = None,
) -> None:
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading=heading,
        body=body,
    )
    dialog.add_response("ok", "OK")
    if copy_text:
        dialog.add_response("copy", "Copy command")

    dialog.set_default_response("ok")
    dialog.set_close_response("ok")

    if copy_text:

        def on_response(_dialog: Adw.MessageDialog, response: str) -> None:
            if response == "copy":
                clipboard = Gdk.Display.get_default().get_clipboard()
                clipboard.set(Gdk.ContentProvider.new_for_value(copy_text))

        dialog.connect("response", on_response)

    dialog.present()


class StatusCard(Gtk.Frame):
    """Compact status summary card."""

    def __init__(
        self,
        title: str,
        *,
        on_activate: Callable[[], None] | None = None,
        compact: bool = False,
    ) -> None:
        super().__init__()
        self.add_css_class("card")
        self.add_css_class("oyster-status-card")
        if compact:
            self.add_css_class("oyster-scan-result-card")
        card_margin = 3 if compact else 6
        self.set_margin_start(card_margin)
        self.set_margin_end(card_margin)
        self.set_margin_top(card_margin)
        self.set_margin_bottom(card_margin)
        self.set_hexpand(True)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2 if compact else 4)
        pad_x = 10 if compact else 16
        pad_y = 6 if compact else 12
        box.set_margin_start(pad_x)
        box.set_margin_end(pad_x)
        box.set_margin_top(pad_y)
        box.set_margin_bottom(pad_y)

        self.title_label = Gtk.Label(label=title)
        self.title_label.set_halign(Gtk.Align.START)
        self.title_label.add_css_class("dim-label")

        self.value_label = Gtk.Label(label="—")
        self.value_label.set_halign(Gtk.Align.START)
        if compact:
            self.value_label.add_css_class("caption")
        else:
            self.value_label.add_css_class("title-2")

        self.desc_label = Gtk.Label(label="")
        self.desc_label.set_halign(Gtk.Align.START)
        self.desc_label.set_wrap(True)
        self.desc_label.add_css_class("dim-label")
        if compact:
            self.desc_label.set_lines(1)
            self.desc_label.set_ellipsize(Pango.EllipsizeMode.END)

        box.append(self.title_label)
        box.append(self.value_label)
        box.append(self.desc_label)
        self.set_child(box)

        if on_activate is not None:
            gesture = Gtk.GestureClick()
            gesture.connect("released", lambda *_: on_activate())
            self.add_controller(gesture)
            self.set_cursor_from_name("pointer")

    def set_values(self, value: str, description: str = "", *, css_class: str = "") -> None:
        self.value_label.set_text(value)
        self.desc_label.set_text(description)
        self.desc_label.set_visible(bool(description.strip()))
        apply_status_css(self.value_label, css_class)


class PreferencesGroup(Adw.PreferencesGroup):
    """Adw.PreferencesGroup with a simple constructor for titled sections."""

    def __init__(self, title: str) -> None:
        super().__init__(title=title)
