"""Confirmation helpers for destructive / privileged CLI actions."""

from __future__ import annotations

import click


def require_confirm(
    confirmed: bool,
    *,
    dry_run: bool = False,
    message: str = "--confirm required",
) -> None:
    """Exit 4 when confirmation is required and missing (unless dry-run)."""
    if dry_run or confirmed:
        return
    click.echo(f"Error: {message}", err=True)
    raise SystemExit(4)
