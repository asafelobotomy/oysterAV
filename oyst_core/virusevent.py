"""ClamAV VirusEvent → oysterAV quarantine / audit bridge (ADR-008 Phase 3).

Reads CLAM_VIRUSEVENT_FILENAME / CLAM_VIRUSEVENT_VIRUSNAME only (never %f).
Does not rewrite host clamd.conf; operators set VirusEvent to the wrapper CLI.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import data_dir, load_config
from oyst_core.events import EventLog
from oyst_core.packs.clamd_onaccess import discover_clamd_conf_paths
from oyst_core.quarantine import QuarantineVault

OYSTERAV_MARK = "oyst-virusevent"
ENV_FILENAME = "CLAM_VIRUSEVENT_FILENAME"
ENV_VIRUSNAME = "CLAM_VIRUSEVENT_VIRUSNAME"


def wrapper_path() -> Path:
    return data_dir() / "bin" / OYSTERAV_MARK


def recommended_virus_event_command(wrapper: Path | None = None) -> str:
    """clamd.conf VirusEvent value (absolute path; no env expansion in conf)."""
    path = wrapper or wrapper_path()
    return str(path.resolve())


def install_wrapper(*, force: bool = False) -> dict[str, object]:
    """Install a small executable that invokes ``oyst-cli virusevent handle``."""
    dest = wrapper_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    oyst = shutil.which("oyst-cli") or "oyst-cli"
    body = (
        "#!/bin/sh\n"
        f"# {OYSTERAV_MARK} — oysterAV VirusEvent handler (ADR-008)\n"
        f'exec "{oyst}" virusevent handle "$@"\n'
    )
    if dest.is_file() and not force:
        existing = dest.read_text(encoding="utf-8")
        if OYSTERAV_MARK in existing:
            return {
                "ok": True,
                "path": str(dest),
                "created": False,
                "virus_event": recommended_virus_event_command(dest),
                "message": "wrapper already present",
            }
    dest.write_text(body, encoding="utf-8")
    dest.chmod(0o755)
    return {
        "ok": True,
        "path": str(dest),
        "created": True,
        "virus_event": recommended_virus_event_command(dest),
        "message": (
            f"Add to host clamd.conf when VirusEvent is unset: "
            f"VirusEvent {recommended_virus_event_command(dest)}"
        ),
    }


def _parse_virus_event(text: str) -> str | None:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "virusevent":
            return parts[1].strip()
    return None


def virusevent_status(*, conf_paths: list[Path] | None = None) -> dict[str, object]:
    """Probe whether host VirusEvent points at the oysterAV wrapper."""
    paths = conf_paths if conf_paths is not None else discover_clamd_conf_paths()
    wrapper = wrapper_path()
    recommended = recommended_virus_event_command(wrapper)
    if not paths:
        return {
            "ok": True,
            "configured": False,
            "owned_by_oysterav": False,
            "handoff": True,
            "conf_path": None,
            "virus_event": None,
            "wrapper_path": str(wrapper),
            "wrapper_installed": wrapper.is_file(),
            "recommended": recommended,
            "message": "no readable clamd conf",
        }
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        value = _parse_virus_event(text)
        if value is None:
            continue
        owned = OYSTERAV_MARK in value or str(wrapper) in value
        foreign = value and not owned
        return {
            "ok": True,
            "configured": True,
            "owned_by_oysterav": owned,
            "handoff": bool(foreign),
            "conf_path": str(path),
            "virus_event": value,
            "wrapper_path": str(wrapper),
            "wrapper_installed": wrapper.is_file(),
            "recommended": recommended,
            "message": (
                "oysterAV owns VirusEvent"
                if owned
                else "foreign VirusEvent — hand off (do not overwrite)"
            ),
        }
    return {
        "ok": True,
        "configured": False,
        "owned_by_oysterav": False,
        "handoff": False,
        "conf_path": str(paths[0]),
        "virus_event": None,
        "wrapper_path": str(wrapper),
        "wrapper_installed": wrapper.is_file(),
        "recommended": recommended,
        "message": "VirusEvent unset — add recommended line when ready",
    }


def _notify(title: str, body: str) -> None:
    notify = shutil.which("notify-send")
    if not notify:
        return
    try:
        subprocess.run(
            [notify, "--app-name=oysterAV", "--urgency=critical", title, body],
            check=False,
            timeout=10,
            capture_output=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def handle_virusevent(
    *,
    env: dict[str, str] | None = None,
    quarantine: bool | None = None,
) -> dict[str, object]:
    """Handle one ClamAV VirusEvent using environment variables only."""
    environ = env if env is not None else dict(os.environ)
    filename = (environ.get(ENV_FILENAME) or "").strip()
    virus = (environ.get(ENV_VIRUSNAME) or "").strip() or "unknown"
    if not filename:
        return {
            "ok": False,
            "error": f"{ENV_FILENAME} missing — refuse to run without env (no %f)",
        }

    path = Path(filename)
    events = EventLog()
    events.log(
        "virusevent",
        f"threat {virus}",
        {"path": filename, "threat": virus},
    )
    SecurityAudit().log(
        "clamav.virusevent",
        "handled",
        success=True,
        data={"path": filename, "threat": virus},
    )

    cfg = load_config()
    do_quarantine = cfg.quarantine.auto if quarantine is None else quarantine
    quarantined = False
    quarantine_error: str | None = None
    if do_quarantine and path.is_file():
        try:
            QuarantineVault().add(str(path), virus)
            quarantined = True
        except (OSError, FileNotFoundError, RuntimeError, ValueError) as exc:
            quarantine_error = str(exc)

    _notify(
        "oysterAV on-access threat",
        f"{virus}\n{filename}" + (" (quarantined)" if quarantined else ""),
    )
    return {
        "ok": True,
        "path": filename,
        "threat": virus,
        "quarantined": quarantined,
        "quarantine_error": quarantine_error,
    }


__all__ = [
    "ENV_FILENAME",
    "ENV_VIRUSNAME",
    "OYSTERAV_MARK",
    "handle_virusevent",
    "install_wrapper",
    "recommended_virus_event_command",
    "virusevent_status",
    "wrapper_path",
]
