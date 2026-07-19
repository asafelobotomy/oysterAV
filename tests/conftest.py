"""Shared pytest fixtures and collection hooks."""

from __future__ import annotations

import importlib.util

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "gui: test requires PyGObject (gi)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    has_gi = importlib.util.find_spec("gi") is not None
    if has_gi:
        return
    skip_gi = pytest.mark.skip(reason="PyGObject (gi) not installed; uv sync --extra gui")
    for item in items:
        path = str(item.fspath)
        if "/test_gui/" in path or item.get_closest_marker("gui"):
            item.add_marker(skip_gi)
