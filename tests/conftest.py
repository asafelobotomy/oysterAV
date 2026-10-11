"""Shared pytest fixtures and collection hooks."""

from __future__ import annotations

import pytest


def _gi_available() -> bool:
    """True when PyGObject imports and the GTK4/libadwaita typelibs exist."""
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
    except (ImportError, ValueError):
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "gui: test requires PyGObject (gi)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _gi_available():
        return
    skip_gi = pytest.mark.skip(reason="PyGObject (gi) not installed; uv sync --extra gui")
    for item in items:
        path = str(item.fspath)
        if "/test_gui/" in path or item.get_closest_marker("gui"):
            item.add_marker(skip_gi)
