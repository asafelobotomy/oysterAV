"""Tests for in-button progress label helper."""

from __future__ import annotations

from oysterav.gui.widgets.progress_button import format_progress_label


def test_format_progress_label() -> None:
    assert format_progress_label("Installing", 0) == "Installing… 0%"
    assert format_progress_label("Removing", 42) == "Removing… 42%"
    assert format_progress_label("Installing", 150) == "Installing… 100%"
