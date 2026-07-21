"""Systemd expire timer for passwordless service-lifecycle grants."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

from oyst_core.privileged.auth_grant_scope import (
    EXPIRE_SCRIPT_PATH,
    EXPIRE_SERVICE_UNIT,
    EXPIRE_TIMER_UNIT,
    GRANT_TTL,
)
from oyst_core.privileged.runner import run_command
from oyst_core.privileged.safe_write import write_text_nofollow

_SYSTEMD_DIR = Path("/etc/systemd/system")


def _expire_script_text(python: str, site_insert: str = "") -> str:
    insert = f"{site_insert}\n" if site_insert else ""
    return textwrap.dedent(
        f"""\
        #!{python}
        {insert}from oyst_core.privileged.auth_grant import revoke_service_lifecycle
        raise SystemExit(0 if revoke_service_lifecycle().get("ok") else 1)
        """,
    )


def _site_insert_from_helper() -> str:
    helper = Path("/usr/lib/oysterav/oyst-helper")
    if not helper.is_file():
        return ""
    try:
        text = helper.read_text(encoding="utf-8")
    except OSError:
        return ""
    lines: list[str] = []
    for line in text.splitlines():
        if "sys.path.insert" in line or line.strip().startswith("import sys"):
            lines.append(line)
        if "oyst_core.privileged.oyst_helper" in line:
            break
    if not lines:
        return ""
    return "\n".join(lines)


def _resolve_expire_python() -> str:
    helper = Path("/usr/lib/oysterav/oyst-helper")
    if helper.is_file():
        try:
            first = helper.read_text(encoding="utf-8").splitlines()[0]
        except OSError:
            first = ""
        if first.startswith("#!"):
            return first[2:].strip() or "/usr/bin/python3"
    return "/usr/bin/python3"


def install_expire_timer(*, prefix: Path | None = None) -> None:
    """Install oneshot timer that revokes the grant after GRANT_TTL."""
    if prefix is not None:
        script = prefix / "usr" / "lib" / "oysterav" / "oyst-auth-expire"
        systemd = prefix / "etc" / "systemd" / "system"
    else:
        script = Path(EXPIRE_SCRIPT_PATH)
        systemd = _SYSTEMD_DIR
    script.parent.mkdir(parents=True, exist_ok=True)
    systemd.mkdir(parents=True, exist_ok=True)
    write_text_nofollow(
        script,
        _expire_script_text(_resolve_expire_python(), _site_insert_from_helper()),
        mode=0o755,
    )
    secs = int(GRANT_TTL.total_seconds())
    service = textwrap.dedent(
        f"""\
        [Unit]
        Description=oysterAV revoke expired passwordless service-lifecycle grant
        [Service]
        Type=oneshot
        ExecStart={script}
        """
    )
    timer = textwrap.dedent(
        f"""\
        [Unit]
        Description=oysterAV passwordless grant expiry
        [Timer]
        OnActiveSec={secs}
        AccuracySec=1min
        Persistent=true
        Unit={EXPIRE_SERVICE_UNIT}
        [Install]
        WantedBy=timers.target
        """
    )
    write_text_nofollow(systemd / EXPIRE_SERVICE_UNIT, service, mode=0o644)
    write_text_nofollow(systemd / EXPIRE_TIMER_UNIT, timer, mode=0o644)
    if prefix is None:
        reload = run_command(["systemctl", "daemon-reload"], timeout=30)
        if reload.returncode != 0:
            raise OSError(
                (reload.stderr or reload.stdout or "systemctl daemon-reload failed").strip(),
            )
        enable = run_command(
            ["systemctl", "enable", "--now", EXPIRE_TIMER_UNIT],
            timeout=30,
        )
        if enable.returncode != 0:
            raise OSError(
                (enable.stderr or enable.stdout or f"failed to enable {EXPIRE_TIMER_UNIT}").strip(),
            )


def remove_expire_timer(*, prefix: Path | None = None) -> None:
    if prefix is not None:
        script = prefix / "usr" / "lib" / "oysterav" / "oyst-auth-expire"
        systemd = prefix / "etc" / "systemd" / "system"
        for name in (EXPIRE_TIMER_UNIT, EXPIRE_SERVICE_UNIT):
            path = systemd / name
            if path.is_file():
                path.unlink()
        if script.is_file():
            script.unlink()
        return
    if os.geteuid() == 0:
        run_command(["systemctl", "disable", "--now", EXPIRE_TIMER_UNIT], timeout=30)
        run_command(["systemctl", "daemon-reload"], timeout=30)
    for name in (EXPIRE_TIMER_UNIT, EXPIRE_SERVICE_UNIT):
        path = _SYSTEMD_DIR / name
        if path.is_file():
            path.unlink()
    script = Path(EXPIRE_SCRIPT_PATH)
    if script.is_file():
        script.unlink()
