"""Apply oysterAV themes via Adw.StyleManager + Gtk.CssProvider."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from oyst_core.ui_theme import DEFAULT_UI_THEME, UiThemeId, normalize_ui_theme
from oysterav.gui.theme.css import build_theme_css
from oysterav.gui.theme.palettes import is_dark_theme, semantic_colors_for

_provider: Gtk.CssProvider | None = None
_provider_added = False
_current_theme: UiThemeId | None = None


def _ensure_provider() -> Gtk.CssProvider:
    global _provider, _provider_added
    if _provider is None:
        _provider = Gtk.CssProvider()
    display = Gdk.Display.get_default()
    if display is not None and not _provider_added:
        Gtk.StyleContext.add_provider_for_display(
            display,
            _provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )
        _provider_added = True
    return _provider


def _set_color_scheme(theme_id: UiThemeId) -> None:
    style = Adw.StyleManager.get_default()
    if theme_id == "system":
        style.set_color_scheme(Adw.ColorScheme.DEFAULT)
    elif is_dark_theme(theme_id):
        style.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else:
        style.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)


def apply_theme(theme_id: str | None = None) -> UiThemeId:
    """Apply a theme by id. Unknown ids fall back to the default Gruvbox Dark Hard."""
    global _current_theme
    resolved = normalize_ui_theme(theme_id)
    colors = semantic_colors_for(resolved)
    css = build_theme_css(colors)
    provider = _ensure_provider()
    provider.load_from_data(css.encode("utf-8"))
    _set_color_scheme(resolved)
    _current_theme = resolved
    return resolved


def current_theme() -> UiThemeId:
    return _current_theme if _current_theme is not None else DEFAULT_UI_THEME


def install_app_stylesheet() -> None:
    """Compat shim: install default theme CSS (same as apply_theme default)."""
    apply_theme(DEFAULT_UI_THEME)
