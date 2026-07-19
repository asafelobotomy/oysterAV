"""CLI output formatters."""

from __future__ import annotations

import json
from typing import Any


def emit(data: Any, *, json_mode: bool = False) -> None:
    if json_mode:
        if hasattr(data, "model_dump"):
            print(json.dumps(data.model_dump(mode="json"), indent=2))
        else:
            print(json.dumps(data, indent=2, default=str))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"{k}: {v}")
        elif isinstance(data, list):
            for item in data:
                print(item)
        else:
            print(data)
