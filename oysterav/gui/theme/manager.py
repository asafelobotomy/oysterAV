"""Apply oysterAV themes via Adw.StyleManager + Gtk.CssProvider."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Gdk", "4.0")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from oyst_core.ui_theme import DEFAULT_UI_THEME, UiThemeId, normalize_ui_theme
from oysterav.gui.theme.css import build_theme_css
from oysterav.gui.theme.palettes import SemanticColors, is_dark_theme, semantic_colors_for
from oysterav.gui.theme.uq_tokens import resolve_uq_theme, tokens_path

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


def _set_color_scheme(theme_id: UiThemeId, *, uq_dark: bool = True) -> None:
    style = Adw.StyleManager.get_default()
    if theme_id == "system":
        style.set_color_scheme(Adw.ColorScheme.DEFAULT)
    elif uq_dark if theme_id == "uq" else is_dark_theme(theme_id):
        style.set_color_scheme(Adw.ColorScheme.FORCE_DARK)
    else:
        style.set_color_scheme(Adw.ColorScheme.FORCE_LIGHT)


def apply_theme(theme_id: str | None = None) -> UiThemeId:
    """Apply a theme by id. Unknown ids fall back to the default uQ theme."""
    global _current_theme
    resolved = normalize_ui_theme(theme_id)
    uq_dark = True
    colors: SemanticColors | None
    if resolved == "uq":
        colors, uq_dark = resolve_uq_theme()
    else:
        colors = semantic_colors_for(resolved)
    css = build_theme_css(colors)
    provider = _ensure_provider()
    provider.load_from_data(css.encode("utf-8"))
    _set_color_scheme(resolved, uq_dark=uq_dark)
    _current_theme = resolved
    return resolved


def current_theme() -> UiThemeId:
    return _current_theme if _current_theme is not None else DEFAULT_UI_THEME


def install_app_stylesheet() -> None:
    """Compat shim: install default theme CSS (same as apply_theme default)."""
    apply_theme(DEFAULT_UI_THEME)


_RELOAD_DELAY_MS = 150
_monitor: Gio.FileMonitor | None = None
_reload_source = 0
_last_tokens: bytes | None = None


def _read_tokens_bytes() -> bytes | None:
    try:
        return tokens_path().read_bytes()
    except OSError:
        return None


def _reload_now() -> bool:
    global _reload_source, _last_tokens
    _reload_source = 0
    data = _read_tokens_bytes()
    if data != _last_tokens:
        _last_tokens = data
        if current_theme() == "uq":
            apply_theme("uq")
    return False


def _on_tokens_event(_monitor: Gio.FileMonitor, file: Gio.File, *_rest: object) -> None:
    global _reload_source
    if file.get_basename() != tokens_path().name:
        return
    if _reload_source:
        GLib.source_remove(_reload_source)
    _reload_source = GLib.timeout_add(_RELOAD_DELAY_MS, _reload_now)


def watch_uq_theme() -> None:
    """Re-apply the uQ theme whenever uQ rewrites tokens.json (live, no restart).

    uqd replaces the file atomically, so the directory is watched.
    """
    global _monitor, _last_tokens
    if _monitor is not None:
        return
    _last_tokens = _read_tokens_bytes()
    directory = tokens_path().parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
        _monitor = Gio.File.new_for_path(str(directory)).monitor_directory(
            Gio.FileMonitorFlags.NONE, None
        )
    except (GLib.Error, OSError):
        return
    _monitor.connect("changed", _on_tokens_event)
