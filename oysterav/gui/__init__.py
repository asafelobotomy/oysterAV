"""GUI package.

``OysterApp`` is imported lazily so pure-Python helpers under ``oysterav.gui``
(finding/dashboard formatting, RPC action wrappers) stay importable — and
testable — on machines without PyGObject.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from oysterav.gui.app import OysterApp

__all__ = ["OysterApp"]


def __getattr__(name: str) -> Any:
    if name == "OysterApp":
        from oysterav.gui.app import OysterApp

        return OysterApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
