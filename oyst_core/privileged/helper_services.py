"""Systemctl + maldet-config + rkhunter-whitelist builders for oyst-helper."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

from oyst_core.packs.rkhunter_resolve import (
    apply_disable_tests_overlay,
    apply_overlay_line,
    apply_overlay_lines,
)
from oyst_core.privileged.validators import (
    validate_monitor_mode,
    validate_systemctl_action,
    validate_unit,
)


def _build_systemctl_argv(argv: Sequence[str]) -> list[str]:
    if len(argv) < 2:
        raise ValueError("usage: systemctl <action> <unit>")
    action = validate_systemctl_action(argv[0])
    unit = validate_unit(argv[1])
    if action == "enable-now":
        return ["systemctl", "enable", "--now", unit]
    if action == "disable-now":
        return ["systemctl", "disable", "--now", unit]
    return ["systemctl", action, unit]


def _apply_maldet_monitor_mode(mode: str) -> None:
    conf_path = Path("/usr/local/maldetect/conf.maldet")
    if not conf_path.is_file():
        raise ValueError(f"maldet config not found: {conf_path}")
    text = conf_path.read_text(encoding="utf-8")
    key = "default_monitor_mode"
    new_line = f'{key}="{mode}"'
    updated: list[str] = []
    found = False
    for line in text.splitlines():
        if line.strip().startswith(f"{key}="):
            updated.append(new_line)
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(new_line)
    conf_path.write_text("\n".join(updated) + "\n", encoding="utf-8")


def _build_maldet_config_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError(
            "usage: maldet-config set-monitor-mode <users|paths> | start-monitor <users|paths>"
        )
    if argv[0] == "set-monitor-mode":
        if len(argv) < 2:
            raise ValueError("usage: maldet-config set-monitor-mode <users|paths>")
        mode = validate_monitor_mode(argv[1])
        _apply_maldet_monitor_mode(mode)
        return ["true"]
    if argv[0] == "start-monitor":
        # One polkit auth: write monitor mode + enable/start maldet unit.
        if len(argv) < 2:
            raise ValueError("usage: maldet-config start-monitor <users|paths>")
        mode = validate_monitor_mode(argv[1])
        _apply_maldet_monitor_mode(mode)
        unit = validate_unit("maldet")
        proc = subprocess.run(
            ["systemctl", "enable", "--now", unit],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "systemctl enable --now failed").strip()
            raise ValueError(detail)
        return ["true"]
    raise ValueError(
        "usage: maldet-config set-monitor-mode <users|paths> | start-monitor <users|paths>"
    )


def _build_rkhunter_whitelist_argv(argv: Sequence[str]) -> list[str]:
    """Write allowlisted directive(s) into /etc/rkhunter.d overlays."""
    if not argv:
        raise ValueError(
            "usage: rkhunter-whitelist set <OPTION> <value> | set-many OPTION=value ... "
            "| set-disable-tests [test ...]"
        )
    if argv[0] == "set":
        if len(argv) < 3:
            raise ValueError("usage: rkhunter-whitelist set <OPTION> <value>")
        apply_overlay_line(argv[1], argv[2])
        return ["true"]
    if argv[0] == "set-many":
        if len(argv) < 2:
            raise ValueError("usage: rkhunter-whitelist set-many OPTION=value ...")
        directives: list[tuple[str, str]] = []
        for item in argv[1:]:
            if "=" not in item:
                raise ValueError(f"expected OPTION=value, got: {item}")
            option, _, value = item.partition("=")
            directives.append((option, value))
        apply_overlay_lines(directives)
        return ["true"]
    if argv[0] == "set-disable-tests":
        apply_disable_tests_overlay(list(argv[1:]))
        return ["true"]
    raise ValueError(
        "usage: rkhunter-whitelist set <OPTION> <value> | set-many OPTION=value ... "
        "| set-disable-tests [test ...]"
    )
