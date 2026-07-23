"""Unified privilege concert dispatcher for oyst-helper."""

from __future__ import annotations

from collections.abc import Sequence

from oyst_core.privileged.helper_clamd import _parse_flag
from oyst_core.privileged.helper_scan_concert import run_scan_concert
from oyst_core.privileged.helper_setup_concert import run_setup_concert
from oyst_core.privileged.helper_setup_harden import run_setup_harden
from oyst_core.privileged.helper_update_concert import run_update_concert

_RECIPES = frozenset({"setup", "harden", "scan-privileged", "update-all"})
_ALIAS_RECIPE = {
    "setup-concert": "setup",
    "setup-harden": "harden",
    "scan-concert": "scan-privileged",
    "update-concert": "update-all",
}


def run_concert(argv: Sequence[str]) -> int:
    """Dispatch by --recipe=… (fail closed on unknown)."""
    recipe = _parse_flag(argv, "recipe")
    if recipe is None:
        raise ValueError(
            "concert requires --recipe=setup|harden|scan-privileged|update-all",
        )
    if recipe not in _RECIPES:
        raise ValueError(f"unknown concert recipe: {recipe}")
    rest = [a for a in argv if not a.startswith("--recipe=")]
    if recipe == "setup":
        return run_setup_concert(rest)
    if recipe == "harden":
        return run_setup_harden(rest)
    if recipe == "update-all":
        return run_update_concert(rest)
    return run_scan_concert(rest)


def run_setup_concert_alias(argv: Sequence[str]) -> int:
    return run_concert([f"--recipe={_ALIAS_RECIPE['setup-concert']}", *argv])


def run_setup_harden_alias(argv: Sequence[str]) -> int:
    return run_concert([f"--recipe={_ALIAS_RECIPE['setup-harden']}", *argv])


def run_scan_concert_alias(argv: Sequence[str]) -> int:
    return run_concert([f"--recipe={_ALIAS_RECIPE['scan-concert']}", *argv])


def run_update_concert_alias(argv: Sequence[str]) -> int:
    return run_concert([f"--recipe={_ALIAS_RECIPE['update-concert']}", *argv])


__all__ = [
    "run_concert",
    "run_scan_concert_alias",
    "run_setup_concert_alias",
    "run_setup_harden_alias",
    "run_update_concert_alias",
]
