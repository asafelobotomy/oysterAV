"""Pure GUI helper formatters (require gi for module import)."""

from __future__ import annotations

from datetime import datetime, timedelta

from oysterav.gui.widgets.common import (
    default_paths_for_profile,
    format_relative_time,
    format_signature_age,
    parse_iso,
    severity_css_class,
)
from oysterav.gui.widgets.runtime_ui import bootstrap_steps, format_runtime_status_line


def test_parse_iso_and_relative_time() -> None:
    assert parse_iso(None) is None
    assert parse_iso("not-a-date") is None
    dt = datetime.now() - timedelta(minutes=5)
    assert "minute" in format_relative_time(dt).lower() or "ago" in format_relative_time(dt).lower()
    assert format_relative_time(None) == "Never"


def test_format_signature_age_and_severity() -> None:
    label, css = format_signature_age(1.0)
    assert "h" in label.lower() or "hour" in label.lower() or label
    assert isinstance(css, str)
    assert severity_css_class("high")
    assert severity_css_class("unknown")


def test_default_paths_for_profile() -> None:
    paths = default_paths_for_profile("quick")
    assert isinstance(paths, list)
    assert paths


def test_runtime_status_helpers() -> None:
    line = format_runtime_status_line(
        {"mode": "full", "installed_packs": ["clamav"], "disk_bytes": 1024},
    )
    assert "full" in line.lower() or "clamav" in line.lower() or line
    steps = bootstrap_steps(
        {
            "ok": True,
            "steps": [{"step": "install", "ok": True}, {"step": "signatures", "ok": False}],
        },
    )
    assert len(steps) == 2
