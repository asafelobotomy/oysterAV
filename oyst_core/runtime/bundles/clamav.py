"""ClamAV portable runtime and signature management."""

from __future__ import annotations

import textwrap
from pathlib import Path

from oyst_core.privileged.runner import run_command
from oyst_core.runtime.manifest import record_artifact, runtime_root
from oyst_core.runtime.progress import ProgressCallback, emit_progress
from oyst_core.runtime.resolver import copy_system_tool, resolve_tool

CLAMAV_DB_DIR = runtime_root() / "clamav" / "db"
CLAMAV_CONF_DIR = runtime_root() / "clamav" / "etc"


def clamav_db_dir() -> Path:
    CLAMAV_DB_DIR.mkdir(parents=True, exist_ok=True)
    return CLAMAV_DB_DIR


def freshclam_conf_path() -> Path:
    CLAMAV_CONF_DIR.mkdir(parents=True, exist_ok=True)
    return CLAMAV_CONF_DIR / "freshclam.conf"


def write_freshclam_conf() -> Path:
    db = clamav_db_dir()
    conf = freshclam_conf_path()
    conf.write_text(
        textwrap.dedent(
            f"""\
            DatabaseDirectory {db}
            DNSDatabaseInfo current.cvd.clamav.net
            DatabaseMirror database.clamav.net
            CompressLocalDatabase yes
            LogTime yes
            NotifyClamd no
            """,
        ),
        encoding="utf-8",
    )
    return conf


def bootstrap_clamav_runtime(*, on_progress: ProgressCallback | None = None) -> dict[str, object]:
    emit_progress(on_progress, "install", 5)
    copied: list[str] = []
    tools = ("clamscan", "freshclam", "clamdscan", "clamd", "clamonacc")
    for idx, tool in enumerate(tools):
        emit_progress(on_progress, "install", 10 + (idx * 10))
        if resolve_tool(tool).path:
            continue
        dest = copy_system_tool(tool)
        if dest:
            copied.append(tool)
            record_artifact(tool, dest, source="system-copy")
    if not resolve_tool("clamscan").path:
        return {
            "ok": False,
            "message": (
                "clamscan not found; install ClamAV on the system once or provide runtime zst"
            ),
        }
    emit_progress(on_progress, "configure", 70)
    write_freshclam_conf()
    emit_progress(on_progress, "signatures", 80)
    sig = update_clamav_signatures()
    ok = sig.get("ok", False)
    emit_progress(on_progress, "install", 100)
    return {
        "ok": ok or bool(copied),
        "message": sig.get("message", f"Copied tools: {', '.join(copied) or 'none'}"),
        "signatures": sig,
        "db_dir": str(clamav_db_dir()),
    }


def update_clamav_signatures() -> dict[str, object]:
    freshclam = resolve_tool("freshclam")
    if not freshclam.path:
        return {"ok": False, "message": "freshclam not available"}
    write_freshclam_conf()
    conf = freshclam_conf_path()
    res = run_command(
        [freshclam.path, f"--config-file={conf}", "--stdout"],
        timeout=3600,
    )
    ok = res.returncode == 0
    has_db = any(clamav_db_dir().glob("*.cvd")) or any(clamav_db_dir().glob("*.cld"))
    return {
        "ok": ok and has_db,
        "message": (res.stderr or res.stdout or "").strip()[:500],
        "has_database": has_db,
    }


def clamscan_database_args() -> list[str]:
    db = clamav_db_dir()
    if any(db.glob("*.cvd")) or any(db.glob("*.cld")):
        return [f"--database={db}"]
    return []
