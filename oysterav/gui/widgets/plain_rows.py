"""Markup-safe constructors for Adw rows and banners.

Adw.PreferencesRow subclasses (and Adw.Banner on some libadwaita releases) parse
their title/subtitle as Pango markup by default. oysterAV interpolates file
paths, audit messages, exception text, firewall rules and news headlines into
those strings, so a ``&`` or ``<`` either blanks the row or lets a crafted
directory name spoof the displayed text. Every row/banner in the GUI is built
through these helpers so ``use_markup`` is always ``False`` and later
``set_title`` / ``set_subtitle`` calls display text literally.

For widgets that have no ``use-markup`` switch (Adw.PreferencesGroup title and
description, Adw.StatusPage description) escape dynamic text with
:func:`escape_markup`.
"""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib  # noqa: E402


def _plain(kwargs: dict[str, Any]) -> dict[str, Any]:
    kwargs["use_markup"] = False
    return kwargs


def action_row(**kwargs: Any) -> Adw.ActionRow:
    return Adw.ActionRow(**_plain(kwargs))


def expander_row(**kwargs: Any) -> Adw.ExpanderRow:
    return Adw.ExpanderRow(**_plain(kwargs))


def switch_row(**kwargs: Any) -> Adw.SwitchRow:
    return Adw.SwitchRow(**_plain(kwargs))


def combo_row(**kwargs: Any) -> Adw.ComboRow:
    return Adw.ComboRow(**_plain(kwargs))


def entry_row(**kwargs: Any) -> Adw.EntryRow:
    return Adw.EntryRow(**_plain(kwargs))


def spin_row(**kwargs: Any) -> Adw.SpinRow:
    return Adw.SpinRow(**_plain(kwargs))


def preferences_row(**kwargs: Any) -> Adw.PreferencesRow:
    return Adw.PreferencesRow(**_plain(kwargs))


def banner(**kwargs: Any) -> Adw.Banner:
    return Adw.Banner(**_plain(kwargs))


def escape_markup(text: object) -> str:
    """Escape *text* for widgets that always parse Pango markup."""
    return str(GLib.markup_escape_text(str(text), -1))
