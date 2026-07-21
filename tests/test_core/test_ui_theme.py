"""Tests for Gruvbox theme palettes and CSS generation (no GTK display)."""

from __future__ import annotations

from oyst_core.ui_theme import (
    DEFAULT_UI_THEME,
    UI_THEME_IDS,
    is_valid_ui_theme,
    normalize_ui_theme,
)
from oysterav.gui.theme.css import ADWAITA_COLOR_NAMES, build_theme_css
from oysterav.gui.theme.palettes import (
    SEMANTIC_REQUIRED_KEYS,
    is_dark_theme,
    semantic_as_dict,
    semantic_colors_for,
)


def test_default_theme_is_gruvbox_dark_hard() -> None:
    assert DEFAULT_UI_THEME == "gruvbox-dark-hard"


def test_all_gruvbox_themes_have_required_semantic_keys() -> None:
    for theme_id in UI_THEME_IDS:
        if theme_id == "system":
            assert semantic_colors_for(theme_id) is None
            continue
        colors = semantic_colors_for(theme_id)
        assert colors is not None, theme_id
        as_dict = semantic_as_dict(colors)
        for key in SEMANTIC_REQUIRED_KEYS:
            assert key in as_dict
            assert as_dict[key], f"{theme_id}.{key} empty"


def test_css_builder_emits_adwaita_defines_for_gruvbox() -> None:
    colors = semantic_colors_for("gruvbox-dark-hard")
    assert colors is not None
    css = build_theme_css(colors)
    for name in ADWAITA_COLOR_NAMES:
        assert f"@define-color {name} " in css
    assert "button.oyster-button" in css
    assert "frame.oyster-status-card" in css
    assert "label.oyster-status-badge" in css
    assert "label.oyster-section-heading" in css
    assert ".oyster-status-bar" in css
    assert "oyster-scan-combo" in css
    assert "label.oyster-update-alert" in css
    assert colors.update_alert in css
    assert colors.success in css
    assert colors.card_bg in css


def test_system_css_is_structural_only() -> None:
    css = build_theme_css(None)
    assert "@define-color" not in css
    assert "button.oyster-button" in css
    assert "frame.oyster-status-card" in css
    assert "oyster-update-alert" in css
    assert "@warning_color" in css
    assert "@card_bg_color" in css


def test_dark_vs_light_detection() -> None:
    assert is_dark_theme("gruvbox-dark-hard")
    assert is_dark_theme("gruvbox-dark-medium")
    assert is_dark_theme("gruvbox-dark-soft")
    assert not is_dark_theme("gruvbox-light-hard")
    assert not is_dark_theme("gruvbox-light-medium")
    assert not is_dark_theme("gruvbox-light-soft")
    assert not is_dark_theme("system")


def test_normalize_and_validate_theme_ids() -> None:
    assert is_valid_ui_theme("gruvbox-dark-soft")
    assert not is_valid_ui_theme("gruvbox-material")
    assert normalize_ui_theme(None) == DEFAULT_UI_THEME
    assert normalize_ui_theme("nope") == DEFAULT_UI_THEME
    assert normalize_ui_theme("gruvbox-light-soft") == "gruvbox-light-soft"
