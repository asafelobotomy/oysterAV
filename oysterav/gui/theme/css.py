"""Build GTK/libadwaita CSS from semantic theme tokens."""

from __future__ import annotations

from oysterav.gui.theme.palettes import SemanticColors

# Structural rules shared by all themes (including System).
_STRUCTURAL_CSS = """
button.oyster-button {
  min-height: 34px;
  padding-top: 6px;
  padding-bottom: 6px;
  padding-left: 14px;
  padding-right: 14px;
}

/* Wide enough for Scan profile labels like Suite / Integrity. */
.oyster-combo dropdown popover.menu contents {
  min-width: 36rem;
}

/* Dashboard / Scan status cards — match Adwaita card chrome. */
frame.oyster-status-card {
  border-radius: 12px;
  padding: 0;
}

frame.oyster-status-card > border {
  border: none;
}

/* Compact status badges in list rows (Clean / threat counts / Installed). */
label.oyster-status-badge {
  font-weight: 600;
  font-size: 0.9em;
  padding-left: 8px;
  padding-right: 8px;
}

/* Section labels used across tabs (Reports detail, Scan packs, wizard). */
label.oyster-section-heading {
  font-weight: 600;
  margin-top: 4px;
  margin-bottom: 2px;
}

/* Scan tab — fit default 960×700 window without vertical scroll. */
frame.oyster-scan-result-card {
  border-radius: 10px;
}

/* Compact profile/target ComboRows (libadwaita ActionRow defaults are taller). */
.oyster-scan-options {
  margin-top: 0;
  margin-bottom: 0;
}

.oyster-scan-options > box {
  margin-top: 0;
  margin-bottom: 0;
}

.oyster-scan-options list {
  background: transparent;
}

.oyster-scan-options row.oyster-scan-combo,
.oyster-scan-options row.oyster-scan-combo.activatable {
  min-height: 0;
  padding-top: 0;
  padding-bottom: 0;
}

.oyster-scan-options row.oyster-scan-combo > box {
  min-height: 28px;
  margin-top: 0;
  margin-bottom: 0;
  padding-top: 4px;
  padding-bottom: 4px;
}

.oyster-scan-options row.oyster-scan-combo title,
.oyster-scan-options row.oyster-scan-combo .title {
  font-size: 0.92em;
}

.oyster-scan-options row.oyster-scan-combo .subtitle,
.oyster-scan-options row.oyster-scan-combo subtitle {
  font-size: 0.88em;
}

.oyster-scan-options .oyster-combo.oyster-scan-combo dropdown popover.menu contents {
  min-width: 26rem;
}

.oyster-scan-options .oyster-combo.oyster-scan-combo dropdown popover.menu listview row,
.oyster-scan-options .oyster-combo.oyster-scan-combo dropdown popover.menu list row,
.oyster-combo.oyster-scan-combo dropdown popover.menu listview row,
.oyster-combo.oyster-scan-combo dropdown popover.menu list row {
  min-height: 26px;
  padding-top: 1px;
  padding-bottom: 1px;
}

button.oyster-scan-run {
  min-height: 30px;
  padding-top: 4px;
  padding-bottom: 4px;
}

label.oyster-section-heading.oyster-scan-section {
  margin-top: 0;
  margin-bottom: 0;
}


/* Shell status bar under the header — fixed-height slot (status / ticker). */
.oyster-status-bar {
  padding-top: 2px;
  padding-bottom: 2px;
  min-height: 22px;
}
"""


def _define_colors(colors: SemanticColors) -> str:
    """Map semantic tokens to libadwaita named colors."""
    pairs = (
        ("window_bg_color", colors.window_bg),
        ("window_fg_color", colors.window_fg),
        ("view_bg_color", colors.view_bg),
        ("view_fg_color", colors.view_fg),
        ("headerbar_bg_color", colors.headerbar_bg),
        ("headerbar_fg_color", colors.headerbar_fg),
        ("headerbar_backdrop_color", colors.headerbar_backdrop),
        ("headerbar_shade_color", colors.headerbar_shade),
        ("headerbar_border_color", colors.borders),
        ("card_bg_color", colors.card_bg),
        ("card_fg_color", colors.card_fg),
        ("card_shade_color", colors.card_shade),
        ("popover_bg_color", colors.popover_bg),
        ("popover_fg_color", colors.popover_fg),
        ("dialog_bg_color", colors.dialog_bg),
        ("dialog_fg_color", colors.dialog_fg),
        ("sidebar_bg_color", colors.sidebar_bg),
        ("sidebar_fg_color", colors.sidebar_fg),
        ("secondary_sidebar_bg_color", colors.sidebar_bg),
        ("secondary_sidebar_fg_color", colors.sidebar_fg),
        ("accent_bg_color", colors.accent_bg),
        ("accent_fg_color", colors.accent_fg),
        ("accent_color", colors.accent),
        ("destructive_bg_color", colors.destructive_bg),
        ("destructive_fg_color", colors.destructive_fg),
        ("destructive_color", colors.destructive),
        ("success_bg_color", colors.success_bg),
        ("success_fg_color", colors.success_fg),
        ("success_color", colors.success),
        ("warning_bg_color", colors.warning_bg),
        ("warning_fg_color", colors.warning_fg),
        ("warning_color", colors.warning),
        ("error_bg_color", colors.error_bg),
        ("error_fg_color", colors.error_fg),
        ("error_color", colors.error),
        ("borders", colors.borders),
        ("shade_color", colors.shade),
    )
    lines = [f"@define-color {name} {value};" for name, value in pairs]
    return "\n".join(lines)


def _themed_widget_rules(colors: SemanticColors) -> str:
    """Explicit widget rules so Frames/labels track Gruvbox tokens consistently."""
    return f"""
frame.oyster-status-card {{
  background-color: {colors.card_bg};
  color: {colors.card_fg};
  border: 1px solid {colors.borders};
}}

.oyster-status-bar {{
  background-color: {colors.headerbar_bg};
  border-bottom: 1px solid {colors.borders};
  color: {colors.window_fg};
}}

label.success, .success {{
  color: {colors.success};
}}

label.warning, .warning {{
  color: {colors.warning};
}}

label.error, .error {{
  color: {colors.error};
}}

label.dim-label {{
  opacity: 0.7;
}}

label.oyster-update-alert {{
  color: {colors.update_alert};
  font-weight: 600;
}}
"""


def _system_widget_rules() -> str:
    """Structural color hooks that defer to Adwaita named colors."""
    return """
frame.oyster-status-card {
  background-color: @card_bg_color;
  color: @card_fg_color;
}

.oyster-status-bar {
  border-bottom: 1px solid alpha(@borders, 0.45);
}

label.oyster-update-alert {
  color: @warning_color;
  font-weight: 600;
}
"""


def build_theme_css(colors: SemanticColors | None) -> str:
    """Return full APPLICATION-priority CSS for the given semantic map.

    When ``colors`` is None (system theme), structural rules plus Adwaita-named
    color references are emitted so desktop theming stays intact.
    """
    if colors is None:
        return (_STRUCTURAL_CSS + _system_widget_rules()).strip() + "\n"
    return (
        _define_colors(colors)
        + "\n\n"
        + _STRUCTURAL_CSS.strip()
        + "\n"
        + _themed_widget_rules(colors).strip()
        + "\n"
    )


# Libadwaita named colors that Gruvbox themes always define (for tests).
ADWAITA_COLOR_NAMES: tuple[str, ...] = (
    "window_bg_color",
    "window_fg_color",
    "view_bg_color",
    "view_fg_color",
    "headerbar_bg_color",
    "headerbar_fg_color",
    "headerbar_backdrop_color",
    "headerbar_shade_color",
    "headerbar_border_color",
    "card_bg_color",
    "card_fg_color",
    "card_shade_color",
    "popover_bg_color",
    "popover_fg_color",
    "dialog_bg_color",
    "dialog_fg_color",
    "sidebar_bg_color",
    "sidebar_fg_color",
    "secondary_sidebar_bg_color",
    "secondary_sidebar_fg_color",
    "accent_bg_color",
    "accent_fg_color",
    "accent_color",
    "destructive_bg_color",
    "destructive_fg_color",
    "destructive_color",
    "success_bg_color",
    "success_fg_color",
    "success_color",
    "warning_bg_color",
    "warning_fg_color",
    "warning_color",
    "error_bg_color",
    "error_fg_color",
    "error_color",
    "borders",
    "shade_color",
)
