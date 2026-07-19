"""Gruvbox palette tokens and per-theme semantic color maps.

Official morhetz Gruvbox colors from gruvbox-contrib color.table.
This module is the sole hex color reference for the oysterAV GUI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from oyst_core.ui_theme import UiThemeId

# --- Raw Gruvbox palette (morhetz) -------------------------------------------------

GRUVBOX: Final[dict[str, str]] = {
    "dark0_hard": "#1d2021",
    "dark0": "#282828",
    "dark0_soft": "#32302f",
    "dark1": "#3c3836",
    "dark2": "#504945",
    "dark3": "#665c54",
    "dark4": "#7c6f64",
    "gray": "#928374",
    "light0_hard": "#f9f5d7",
    "light0": "#fbf1c7",
    "light0_soft": "#f2e5bc",
    "light1": "#ebdbb2",
    "light2": "#d5c4a1",
    "light3": "#bdae93",
    "light4": "#a89984",
    "bright_red": "#fb4934",
    "bright_green": "#b8bb26",
    "bright_yellow": "#fabd2f",
    "bright_blue": "#83a598",
    "bright_purple": "#d3869b",
    "bright_aqua": "#8ec07c",
    "bright_orange": "#fe8019",
    "neutral_red": "#cc241d",
    "neutral_green": "#98971a",
    "neutral_yellow": "#d79921",
    "neutral_blue": "#458588",
    "neutral_purple": "#b16286",
    "neutral_aqua": "#689d6a",
    "neutral_orange": "#d65d0e",
    "faded_red": "#9d0006",
    "faded_green": "#79740e",
    "faded_yellow": "#b57614",
    "faded_blue": "#076678",
    "faded_purple": "#8f3f71",
    "faded_aqua": "#427b58",
    "faded_orange": "#af3a03",
}


@dataclass(frozen=True, slots=True)
class SemanticColors:
    """Libadwaita-oriented semantic tokens derived from a Gruvbox variant."""

    window_bg: str
    window_fg: str
    view_bg: str
    view_fg: str
    headerbar_bg: str
    headerbar_fg: str
    headerbar_backdrop: str
    headerbar_shade: str
    card_bg: str
    card_fg: str
    card_shade: str
    popover_bg: str
    popover_fg: str
    dialog_bg: str
    dialog_fg: str
    sidebar_bg: str
    sidebar_fg: str
    accent_bg: str
    accent_fg: str
    accent: str
    destructive_bg: str
    destructive_fg: str
    destructive: str
    success_bg: str
    success_fg: str
    success: str
    warning_bg: str
    warning_fg: str
    warning: str
    error_bg: str
    error_fg: str
    error: str
    borders: str
    shade: str
    update_alert: str


def _g(name: str) -> str:
    return GRUVBOX[name]


def _dark_semantic(bg0: str) -> SemanticColors:
    """Bright accents on a dark bg0 (hard / medium / soft)."""
    bg1 = _g("dark1")
    bg2 = _g("dark2")
    fg = _g("light1")
    accent = _g("bright_orange")
    accent_bg = _g("neutral_orange")
    success = _g("bright_green")
    warning = _g("bright_yellow")
    error = _g("bright_red")
    return SemanticColors(
        window_bg=bg0,
        window_fg=fg,
        view_bg=bg0,
        view_fg=fg,
        headerbar_bg=bg1,
        headerbar_fg=fg,
        headerbar_backdrop=bg0,
        headerbar_shade="rgba(0, 0, 0, 0.36)",
        card_bg=bg1,
        card_fg=fg,
        card_shade="rgba(0, 0, 0, 0.36)",
        popover_bg=bg1,
        popover_fg=fg,
        dialog_bg=bg1,
        dialog_fg=fg,
        sidebar_bg=bg1,
        sidebar_fg=fg,
        accent_bg=accent_bg,
        accent_fg=_g("light0_hard"),
        accent=accent,
        destructive_bg=_g("neutral_red"),
        destructive_fg=_g("light0_hard"),
        destructive=error,
        success_bg=_g("neutral_green"),
        success_fg=_g("light0_hard"),
        success=success,
        warning_bg=_g("neutral_yellow"),
        warning_fg=_g("dark0_hard"),
        warning=warning,
        error_bg=_g("neutral_red"),
        error_fg=_g("light0_hard"),
        error=error,
        borders=bg2,
        shade="rgba(0, 0, 0, 0.36)",
        update_alert=warning,
    )


def _light_semantic(bg0: str) -> SemanticColors:
    """Faded accents on a light bg0 (hard / medium / soft)."""
    bg1 = _g("light1")
    bg2 = _g("light2")
    fg = _g("dark1")
    accent = _g("faded_orange")
    accent_bg = _g("neutral_orange")
    success = _g("faded_green")
    warning = _g("faded_yellow")
    error = _g("faded_red")
    return SemanticColors(
        window_bg=bg0,
        window_fg=fg,
        view_bg=bg0,
        view_fg=fg,
        headerbar_bg=bg1,
        headerbar_fg=fg,
        headerbar_backdrop=bg0,
        headerbar_shade="rgba(0, 0, 0, 0.12)",
        card_bg=_g("light0"),
        card_fg=fg,
        card_shade="rgba(0, 0, 0, 0.12)",
        popover_bg=_g("light0"),
        popover_fg=fg,
        dialog_bg=_g("light0"),
        dialog_fg=fg,
        sidebar_bg=bg1,
        sidebar_fg=fg,
        accent_bg=accent_bg,
        accent_fg=_g("light0_hard"),
        accent=accent,
        destructive_bg=_g("neutral_red"),
        destructive_fg=_g("light0_hard"),
        destructive=error,
        success_bg=_g("neutral_green"),
        success_fg=_g("light0_hard"),
        success=success,
        warning_bg=_g("neutral_yellow"),
        warning_fg=_g("dark0_hard"),
        warning=warning,
        error_bg=_g("neutral_red"),
        error_fg=_g("light0_hard"),
        error=error,
        borders=bg2,
        shade="rgba(0, 0, 0, 0.12)",
        update_alert=warning,
    )


# Per-variant bg0 keys into GRUVBOX.
_THEME_BG0: Final[dict[str, str]] = {
    "gruvbox-dark-hard": "dark0_hard",
    "gruvbox-dark-medium": "dark0",
    "gruvbox-dark-soft": "dark0_soft",
    "gruvbox-light-hard": "light0_hard",
    "gruvbox-light-medium": "light0",
    "gruvbox-light-soft": "light0_soft",
}

_DARK_THEME_IDS: Final[frozenset[str]] = frozenset(
    {
        "gruvbox-dark-hard",
        "gruvbox-dark-medium",
        "gruvbox-dark-soft",
    }
)

SEMANTIC_REQUIRED_KEYS: Final[tuple[str, ...]] = (
    "window_bg",
    "window_fg",
    "view_bg",
    "view_fg",
    "headerbar_bg",
    "headerbar_fg",
    "headerbar_backdrop",
    "headerbar_shade",
    "card_bg",
    "card_fg",
    "card_shade",
    "popover_bg",
    "popover_fg",
    "dialog_bg",
    "dialog_fg",
    "sidebar_bg",
    "sidebar_fg",
    "accent_bg",
    "accent_fg",
    "accent",
    "destructive_bg",
    "destructive_fg",
    "destructive",
    "success_bg",
    "success_fg",
    "success",
    "warning_bg",
    "warning_fg",
    "warning",
    "error_bg",
    "error_fg",
    "error",
    "borders",
    "shade",
    "update_alert",
)


def is_dark_theme(theme_id: UiThemeId | str) -> bool:
    return theme_id in _DARK_THEME_IDS


def semantic_colors_for(theme_id: UiThemeId | str) -> SemanticColors | None:
    """Return semantic colors for a Gruvbox theme id, or None for ``system``."""
    if theme_id == "system":
        return None
    bg0_key = _THEME_BG0.get(theme_id)
    if bg0_key is None:
        return None
    bg0 = _g(bg0_key)
    if is_dark_theme(theme_id):
        return _dark_semantic(bg0)
    return _light_semantic(bg0)


def semantic_as_dict(colors: SemanticColors) -> dict[str, str]:
    return {key: getattr(colors, key) for key in SEMANTIC_REQUIRED_KEYS}
