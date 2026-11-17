"""uQ tokens.json -> semantic colors (no GTK display)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oysterav.gui.theme.css import ADWAITA_COLOR_NAMES, build_theme_css
from oysterav.gui.theme.uq_tokens import (
    load_tokens,
    parse_tokens,
    resolve_uq_theme,
    semantic_from_tokens,
    tokens_are_dark,
    tokens_path,
)

COLORS = {
    "bg": "#282828",
    "surface": "#343330",
    "surface_alt": "#3d3c37",
    "overlay": "#4f4c44",
    "text": "#ebdbb2",
    "text_muted": "#b0a589",
    "accent": "#d79921",
    "accent_text": "#282828",
    "border": "#625e51",
    "success": "#98971a",
    "warning": "#d79921",
    "error": "#cc241d",
}


def _doc(**over: object) -> str:
    return json.dumps({"id": "gruvbox", "variant": "dark", "colors": COLORS, **over})


def test_tokens_path_honours_xdg_state_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "/x/state")
    assert tokens_path() == Path("/x/state/uq/theme/tokens.json")


def test_parse_rejects_malformed_and_incomplete() -> None:
    assert parse_tokens("not json") is None
    assert parse_tokens("[]") is None
    assert parse_tokens(json.dumps({"colors": {"bg": "#000000"}})) is None
    bad = dict(COLORS, accent="red")
    assert parse_tokens(json.dumps({"colors": bad})) is None


def test_semantic_mapping_and_css() -> None:
    tokens = parse_tokens(_doc())
    assert tokens is not None
    colors = semantic_from_tokens(tokens)
    assert colors.window_bg == COLORS["bg"]
    assert colors.card_bg == COLORS["surface"]
    assert colors.accent_bg == COLORS["accent"]
    assert colors.accent_fg == COLORS["accent_text"]
    css = build_theme_css(colors)
    for name in ADWAITA_COLOR_NAMES:
        assert f"@define-color {name} " in css
    assert COLORS["bg"] in css


def test_dark_flag_uses_variant_then_luminance() -> None:
    dark = parse_tokens(_doc())
    assert dark is not None and tokens_are_dark(dark)
    light = parse_tokens(_doc(variant="light"))
    assert light is not None and not tokens_are_dark(light)
    noflag = parse_tokens(json.dumps({"colors": dict(COLORS, bg="#fbf1c7")}))
    assert noflag is not None and not tokens_are_dark(noflag)


def test_resolve_reads_file_and_falls_back(tmp_path: Path) -> None:
    f = tmp_path / "tokens.json"
    assert load_tokens(f) is None
    colors, dark = resolve_uq_theme(f)
    assert dark and colors.window_bg == "#1d2021"  # Gruvbox Dark Hard fallback
    f.write_text(_doc(variant="light"))
    colors, dark = resolve_uq_theme(f)
    assert not dark and colors.window_bg == COLORS["bg"]
    f.write_text("{broken")
    assert resolve_uq_theme(f)[0].window_bg == "#1d2021"
