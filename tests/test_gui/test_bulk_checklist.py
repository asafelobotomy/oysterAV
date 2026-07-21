"""Tests for bulk checklist helpers and quarantine path formatting."""

from __future__ import annotations

from oysterav.gui.widgets.bulk_checklist import format_capped_list


def test_format_capped_list_empty() -> None:
    assert format_capped_list([]) == ""


def test_format_capped_list_caps_with_more() -> None:
    items = [f"/tmp/f{i}" for i in range(12)]
    text = format_capped_list(items, limit=8)
    assert "• /tmp/f0" in text
    assert "(+4 more)" in text
    assert "/tmp/f11" not in text
