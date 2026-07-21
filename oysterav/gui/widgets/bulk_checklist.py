"""Shared Adw.ExpanderRow checklist for bulk Install/Update/Apply actions."""

from __future__ import annotations

from collections.abc import Callable, Sequence

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.widgets.common import make_button


def make_bulk_expander(
    title: str,
    *,
    subtitle: str = "",
    expanded: bool = True,
) -> Adw.ExpanderRow:
    """Collapsible list header for 'what this bulk action includes'."""
    expander = Adw.ExpanderRow(title=title)
    if subtitle:
        expander.set_subtitle(subtitle)
    expander.set_expanded(expanded)
    return expander


def add_action_item(
    expander: Adw.ExpanderRow,
    *,
    title: str,
    subtitle: str = "",
    button_label: str | None = None,
    on_clicked: Callable[[], None] | None = None,
    suggested: bool = False,
) -> Adw.ActionRow:
    """Add one checklist row; optional suffix button."""
    row = Adw.ActionRow(title=title)
    if subtitle:
        row.set_subtitle(subtitle)
    if button_label and on_clicked is not None:
        btn = make_button(button_label, suggested=suggested, row_suffix=True)
        btn.connect("clicked", lambda *_: on_clicked())
        row.add_suffix(btn)
    expander.add_row(row)
    return row


def add_switch_item(
    expander: Adw.ExpanderRow,
    *,
    title: str,
    subtitle: str = "",
    active: bool = True,
) -> Adw.SwitchRow:
    """Add a toggleable checklist row (included in bulk when active)."""
    row = Adw.SwitchRow(title=title)
    if subtitle:
        row.set_subtitle(subtitle)
    row.set_active(active)
    expander.add_row(row)
    return row


def format_capped_list(items: Sequence[str], *, limit: int = 8) -> str:
    """Bullet-friendly capped list for dialogs / confirm bodies."""
    cleaned = [str(i).strip() for i in items if str(i).strip()]
    if not cleaned:
        return ""
    shown = cleaned[:limit]
    lines = [f"  • {item}" for item in shown]
    extra = len(cleaned) - len(shown)
    if extra > 0:
        lines.append(f"  • (+{extra} more)")
    return "\n".join(lines)


__all__ = [
    "add_action_item",
    "add_switch_item",
    "format_capped_list",
    "make_bulk_expander",
]
