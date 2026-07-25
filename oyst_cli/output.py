"""CLI output formatters."""

from __future__ import annotations

import json
import sys
from typing import Any

from oyst_core.terminal_log import log_raw, log_structured


def _format_text(data: Any, *, json_mode: bool) -> str:
    if json_mode:
        if hasattr(data, "model_dump"):
            return json.dumps(data.model_dump(mode="json"), indent=2)
        return json.dumps(data, indent=2, default=str)
    if isinstance(data, dict):
        return "\n".join(f"{k}: {v}" for k, v in data.items())
    if isinstance(data, list):
        return "\n".join(str(item) for item in data)
    return str(data)


def _skip_transcript() -> bool:
    return "terminal" in sys.argv[1:3]


def emit(data: Any, *, json_mode: bool = False) -> None:
    text = _format_text(data, json_mode=json_mode)
    if not _skip_transcript():
        try:
            summary = text.splitlines()[0] if text else "(empty)"
            if len(summary) > 120:
                summary = summary[:117] + "…"
            log_structured("cli", "emit", f"command result: {summary}")
            log_raw("cli", "emit", text if text else "(empty)")
        except Exception:  # noqa: BLE001 — never break CLI for transcript
            pass
    print(text)
