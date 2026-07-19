"""Single reference library for oysterAV GUI theme, color, and styling."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.ui_theme import (
    DEFAULT_UI_THEME,
    UI_THEME_IDS,
    UI_THEME_LABELS,
    UiThemeId,
    is_valid_ui_theme,
    normalize_ui_theme,
)
from oysterav.gui.theme.css import ADWAITA_COLOR_NAMES, build_theme_css
from oysterav.gui.theme.palettes import (
    GRUVBOX,
    SEMANTIC_REQUIRED_KEYS,
    SemanticColors,
    is_dark_theme,
    semantic_as_dict,
    semantic_colors_for,
)

if TYPE_CHECKING:
    from oysterav.gui.theme.manager import apply_theme as apply_theme
    from oysterav.gui.theme.manager import current_theme as current_theme
    from oysterav.gui.theme.manager import install_app_stylesheet as install_app_stylesheet

DEFAULT_THEME = DEFAULT_UI_THEME
THEME_IDS = UI_THEME_IDS


def theme_display_name(theme_id: str) -> str:
    label = UI_THEME_LABELS.get(theme_id)  # type: ignore[call-overload]
    return label if label is not None else theme_id


def __getattr__(name: str) -> Any:
    """Lazy-load GTK-backed manager APIs so palette/CSS tests need no display."""
    if name in ("apply_theme", "current_theme", "install_app_stylesheet"):
        from oysterav.gui.theme import manager as _manager

        return getattr(_manager, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ADWAITA_COLOR_NAMES",
    "DEFAULT_THEME",
    "DEFAULT_UI_THEME",
    "GRUVBOX",
    "SEMANTIC_REQUIRED_KEYS",
    "THEME_IDS",
    "UI_THEME_IDS",
    "UI_THEME_LABELS",
    "SemanticColors",
    "UiThemeId",
    "apply_theme",
    "build_theme_css",
    "current_theme",
    "install_app_stylesheet",
    "is_dark_theme",
    "is_valid_ui_theme",
    "normalize_ui_theme",
    "semantic_as_dict",
    "semantic_colors_for",
    "theme_display_name",
]
