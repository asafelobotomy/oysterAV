"""Shared Click option decorators for oyst-cli."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import click


def json_option[F: Callable[..., Any]](func: F) -> F:
    """Add a standard ``--json`` flag bound to ``json_mode``."""
    return click.option("--json", "json_mode", is_flag=True)(func)


def progress_option[F: Callable[..., Any]](func: F) -> F:
    """Add ``--progress`` (NDJSON on stderr) bound to ``show_progress``."""
    return click.option(
        "--progress",
        "show_progress",
        is_flag=True,
        help="Emit NDJSON progress events on stderr",
    )(func)
