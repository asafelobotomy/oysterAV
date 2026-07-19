"""UI theme identifiers shared by config and the GTK theme library.

Color/CSS tokens live only in ``oysterav.gui.theme``; this module is the
config-safe allowlist (no GTK imports).
"""

from __future__ import annotations

from typing import Literal

UiThemeId = Literal[
    "system",
    "gruvbox-dark-hard",
    "gruvbox-dark-medium",
    "gruvbox-dark-soft",
    "gruvbox-light-hard",
    "gruvbox-light-medium",
    "gruvbox-light-soft",
]

DEFAULT_UI_THEME: UiThemeId = "gruvbox-dark-hard"

UI_THEME_IDS: tuple[UiThemeId, ...] = (
    "system",
    "gruvbox-dark-hard",
    "gruvbox-dark-medium",
    "gruvbox-dark-soft",
    "gruvbox-light-hard",
    "gruvbox-light-medium",
    "gruvbox-light-soft",
)

UI_THEME_ID_SET: frozenset[str] = frozenset(UI_THEME_IDS)

UI_THEME_LABELS: dict[UiThemeId, str] = {
    "system": "System (Adwaita)",
    "gruvbox-dark-hard": "Gruvbox Dark Hard",
    "gruvbox-dark-medium": "Gruvbox Dark Medium",
    "gruvbox-dark-soft": "Gruvbox Dark Soft",
    "gruvbox-light-hard": "Gruvbox Light Hard",
    "gruvbox-light-medium": "Gruvbox Light Medium",
    "gruvbox-light-soft": "Gruvbox Light Soft",
}


def is_valid_ui_theme(theme_id: str) -> bool:
    return theme_id in UI_THEME_ID_SET


def normalize_ui_theme(theme_id: str | None) -> UiThemeId:
    if theme_id and theme_id in UI_THEME_ID_SET:
        return theme_id  # type: ignore[return-value]
    return DEFAULT_UI_THEME
