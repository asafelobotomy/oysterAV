"""Tests for in-button progress label helper."""

from __future__ import annotations

import pytest

pytest.importorskip("gi", reason="PyGObject (gi) not installed", exc_type=ImportError)

from oysterav.gui.widgets.progress_button import format_progress_label  # noqa: E402


def test_format_progress_label() -> None:
    assert format_progress_label("Installing", 0) == "Installing… 0%"
    assert format_progress_label("Removing", 42) == "Removing… 42%"
    assert format_progress_label("Installing", 150) == "Installing… 100%"
