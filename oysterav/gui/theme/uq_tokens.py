"""Read uQ's rendered theme (``tokens.json``) and map it to oysterAV semantic colors.

uQ's daemon renders the active theme to ``$XDG_STATE_HOME/uq/theme/tokens.json``
(default ``~/.local/state/uq/theme``). Finding and checking the file is uQ's shared
uq-theme module (``uq_theme.py``, vendored unchanged), so oysterAV reads it exactly as
uQ's other apps do. No GTK imports here, so it is testable without a display.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oysterav.gui.theme import uq_theme
from oysterav.gui.theme.palettes import SemanticColors, semantic_colors_for


def tokens_path() -> Path:
    """``$XDG_STATE_HOME/uq/theme/tokens.json`` (an absolute one only, as uQ), else under
    ``~/.local/state``."""
    path = uq_theme.tokens_path()
    return Path(path) if path is not None else Path.home() / ".local/state/uq/theme/tokens.json"


def _present(tokens: Any) -> dict[str, Any] | None:
    return tokens if isinstance(tokens, dict) and tokens.get("present") else None


def parse_tokens(text: str) -> dict[str, Any] | None:
    """Return the parsed tokens, or None when malformed or incomplete. ``variant`` is None when
    the file names none (uq_theme reads that as dark; oysterAV goes by the background)."""
    tokens = _present(uq_theme.parse(text))
    if tokens is not None and json.loads(text).get("variant") not in ("dark", "light"):
        tokens["variant"] = None
    return tokens


def load_tokens(path: Path | None = None) -> dict[str, Any] | None:
    try:
        with open(path or tokens_path(), "rb") as f:
            data = f.read(uq_theme.MAX_BYTES + 1)
        if len(data) > uq_theme.MAX_BYTES:
            return None
        return parse_tokens(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return None


def _luminance(color: str) -> float:
    r, g, b = (int(color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _on(color: str) -> str:
    """Readable foreground for text drawn on ``color``."""
    return "#ffffff" if _luminance(color) < 0.5 else "#1a1a1a"


def tokens_are_dark(tokens: dict[str, Any]) -> bool:
    variant = tokens.get("variant")
    if variant in ("dark", "light"):
        return bool(variant == "dark")
    return _luminance(tokens["colors"]["bg"]) < 0.5


def semantic_from_tokens(tokens: dict[str, Any]) -> SemanticColors:
    c = tokens["colors"]
    shade = "rgba(0, 0, 0, 0.36)" if tokens_are_dark(tokens) else "rgba(0, 0, 0, 0.12)"
    return SemanticColors(
        window_bg=c["bg"],
        window_fg=c["text"],
        view_bg=c["bg"],
        view_fg=c["text"],
        headerbar_bg=c["surface"],
        headerbar_fg=c["text"],
        headerbar_backdrop=c["bg"],
        headerbar_shade=shade,
        card_bg=c["surface"],
        card_fg=c["text"],
        card_shade=shade,
        popover_bg=c["surface_alt"],
        popover_fg=c["text"],
        dialog_bg=c["surface"],
        dialog_fg=c["text"],
        sidebar_bg=c["surface"],
        sidebar_fg=c["text"],
        accent_bg=c["accent"],
        accent_fg=c["accent_text"],
        accent=c["accent"],
        destructive_bg=c["error"],
        destructive_fg=_on(c["error"]),
        destructive=c["error"],
        success_bg=c["success"],
        success_fg=_on(c["success"]),
        success=c["success"],
        warning_bg=c["warning"],
        warning_fg=_on(c["warning"]),
        warning=c["warning"],
        error_bg=c["error"],
        error_fg=_on(c["error"]),
        error=c["error"],
        borders=c["border"],
        shade=shade,
        update_alert=c["warning"],
    )


def resolve_uq_theme(path: Path | None = None) -> tuple[SemanticColors, bool]:
    """Colors and dark flag for the uQ theme; Gruvbox Dark Hard when uQ is absent."""
    tokens = load_tokens(path)
    if tokens is not None:
        return semantic_from_tokens(tokens), tokens_are_dark(tokens)
    fallback = semantic_colors_for("gruvbox-dark-hard")
    assert fallback is not None
    return fallback, True
