"""SQLite event log and scan history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from oyst_core.config import data_dir
from oyst_core.finding_status import open_findings_count, scan_is_clean

_JOB_CANCEL_DDL = (
    "CREATE TABLE IF NOT EXISTS job_cancel ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "requested INTEGER NOT NULL)"
)


class EventLog:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (data_dir() / "events.db")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_cancel_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(_JOB_CANCEL_DDL)
        conn.execute("INSERT OR IGNORE INTO job_cancel (id, requested) VALUES (1, 0)")

    def _ensure_job_progress_schema(self, conn: sqlite3.Connection) -> None:
        cols = {str(row[1]) for row in conn.execute("PRAGMA table_info(job_lock)").fetchall()}
        if "pack" not in cols:
            conn.execute("ALTER TABLE job_lock ADD COLUMN pack TEXT")
        if "message" not in cols:
            conn.execute("ALTER TABLE job_lock ADD COLUMN message TEXT")
        if "percent" not in cols:
            conn.execute("ALTER TABLE job_lock ADD COLUMN percent REAL DEFAULT 0")
        if "state" not in cols:
            conn.execute("ALTER TABLE job_lock ADD COLUMN state TEXT")

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data TEXT
                );
                CREATE TABLE IF NOT EXISTS scan_history (
                    job_id TEXT PRIMARY KEY,
                    profile TEXT NOT NULL,
                    paths TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    clean INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    result_json TEXT
                );
                CREATE TABLE IF NOT EXISTS job_lock (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    job_id TEXT,
                    started_at TEXT
                );
                INSERT OR IGNORE INTO job_lock (id, job_id, started_at) VALUES (1, NULL, NULL);
                """
            )
            self._ensure_cancel_schema(conn)
            self._ensure_job_progress_schema(conn)

    def log(self, kind: str, message: str, data: dict[str, Any] | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (ts, kind, message, data) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), kind, message, json.dumps(data or {})),
            )

    def history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return slim scan rows (no full result_json) for list UIs."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            raw = dict(row)
            paths = self._decode_paths(raw.get("paths"))
            state = "completed"
            has_errors = False
            open_count: int | None = None
            result_raw = raw.get("result_json")
            if isinstance(result_raw, str) and result_raw:
                try:
                    parsed = json.loads(result_raw)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, dict):
                    if parsed.get("state"):
                        state = str(parsed["state"])
                    errs = parsed.get("pack_errors")
                    has_errors = isinstance(errs, list) and len(errs) > 0
                    findings = parsed.get("findings")
                    if isinstance(findings, list):
                        open_count = open_findings_count(findings)
            findings_count = int(raw["findings_count"] or 0)
            out.append(
                {
                    "job_id": raw["job_id"],
                    "profile": raw["profile"],
                    "paths": paths,
                    "started_at": raw["started_at"],
                    "finished_at": raw["finished_at"],
                    "clean": bool(raw["clean"]),
                    "findings_count": findings_count,
                    "open_findings_count": (
                        open_count if open_count is not None else findings_count
                    ),
                    "state": state,
                    "has_errors": has_errors,
                }
            )
        return out

    def get_scan(self, job_id: str) -> dict[str, Any] | None:
        """Return the full persisted ScanResult dict for *job_id*, or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json FROM scan_history WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        result_raw = row["result_json"]
        if not isinstance(result_raw, str) or not result_raw:
            return None
        try:
            parsed = json.loads(result_raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def delete_scan(self, job_id: str) -> dict[str, Any]:
        """Delete one scan history row by job id."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM scan_history WHERE job_id = ?",
                (job_id,),
            )
            deleted = int(cur.rowcount or 0)
        if deleted == 0:
            return {"ok": False, "error": f"scan not found: {job_id}", "deleted": 0}
        return {"ok": True, "deleted": 1, "job_id": job_id}

    def delete_all_scans(self) -> dict[str, Any]:
        """Delete every scan history row."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scan_history")
            deleted = int(cur.rowcount or 0)
        return {"ok": True, "deleted": deleted}

    def list_full_scans(self, *, limit: int = 500) -> list[dict[str, Any]]:
        """Return full result_json payloads for recent scans (newest first)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT result_json FROM scan_history
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            result_raw = row["result_json"]
            if not isinstance(result_raw, str) or not result_raw:
                continue
            try:
                parsed = json.loads(result_raw)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
        return out

    @staticmethod
    def _decode_paths(raw: object) -> list[str]:
        if isinstance(raw, list):
            return [str(p) for p in raw]
        if not isinstance(raw, str) or not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [str(p) for p in parsed]
        return []

    def save_scan(self, result: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_history (
                    job_id, profile, paths, started_at, finished_at,
                    clean, findings_count, result_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["job_id"],
                    result["profile"],
                    json.dumps(result.get("paths", [])),
                    result["started_at"],
                    result.get("finished_at"),
                    1 if result.get("clean", True) else 0,
                    len(result.get("findings", [])),
                    json.dumps(result),
                ),
            )

    def patch_finding(
        self,
        job_id: str,
        *,
        pack: str,
        path: str,
        threat_name: str,
        message: str = "",
        quarantined: bool | None = None,
        resolved: bool | None = None,
    ) -> dict[str, Any]:
        """Update flags on one finding in a stored scan; recompute clean."""
        result = self.get_scan(job_id)
        if result is None:
            return {"ok": False, "error": f"scan not found: {job_id}"}
        findings = result.get("findings")
        if not isinstance(findings, list):
            return {"ok": False, "error": "scan has no findings list"}
        matched = False
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if (
                str(finding.get("pack") or "") == pack
                and str(finding.get("path") or "") == path
                and str(finding.get("threat_name") or "") == threat_name
                and str(finding.get("message") or "") == message
            ):
                if quarantined is not None:
                    finding["quarantined"] = quarantined
                if resolved is not None:
                    finding["resolved"] = resolved
                matched = True
                break
        if not matched:
            # Fallback: match without message (parsers may differ slightly).
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                if (
                    str(finding.get("pack") or "") == pack
                    and str(finding.get("path") or "") == path
                    and str(finding.get("threat_name") or "") == threat_name
                ):
                    if quarantined is not None:
                        finding["quarantined"] = quarantined
                    if resolved is not None:
                        finding["resolved"] = resolved
                    matched = True
                    break
        if not matched:
            return {"ok": False, "error": "finding not found in scan"}
        result["findings"] = findings
        result["clean"] = scan_is_clean(findings)
        self.save_scan(result)
        return {"ok": True, "clean": result["clean"], "job_id": job_id}

    def acquire_job_lock(self, job_id: str) -> bool:
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
            if row and row["job_id"]:
                return False
            conn.execute(
                """
                UPDATE job_lock SET
                    job_id = ?, started_at = ?,
                    pack = NULL, message = 'Starting', percent = 0, state = 'running'
                WHERE id = 1
                """,
                (job_id, datetime.now().isoformat()),
            )
            self._ensure_cancel_schema(conn)
            conn.execute("UPDATE job_cancel SET requested = 0 WHERE id = 1")
            return True

    def set_job_progress(
        self,
        job_id: str,
        *,
        pack: str = "",
        message: str = "",
        percent: float = 0.0,
        state: str = "running",
    ) -> None:
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            conn.execute(
                """
                UPDATE job_lock SET
                    pack = ?, message = ?, percent = ?, state = ?
                WHERE id = 1 AND job_id = ?
                """,
                (pack or None, message or None, float(percent), state, job_id),
            )

    def get_job_progress(self) -> dict[str, Any]:
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            row = conn.execute("SELECT * FROM job_lock WHERE id = 1").fetchone()
        if row is None or not row["job_id"]:
            return {
                "active": False,
                "job_id": None,
                "started_at": None,
                "pack": "",
                "message": "",
                "percent": 0.0,
                "state": "",
            }
        return {
            "active": True,
            "job_id": str(row["job_id"]),
            "started_at": row["started_at"],
            "pack": str(row["pack"] or ""),
            "message": str(row["message"] or ""),
            "percent": float(row["percent"] or 0),
            "state": str(row["state"] or "running"),
        }

    def release_job_lock(self, job_id: str) -> None:
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            conn.execute(
                """
                UPDATE job_lock SET
                    job_id = NULL, started_at = NULL,
                    pack = NULL, message = NULL, percent = 0, state = NULL
                WHERE id = 1 AND job_id = ?
                """,
                (job_id,),
            )
            self._ensure_cancel_schema(conn)
            conn.execute("UPDATE job_cancel SET requested = 0 WHERE id = 1")

    def request_cancel(self, job_id: str | None = None) -> bool:
        """Mark the active job for cooperative cancellation. Returns True if a job was active."""
        with self._connect() as conn:
            self._ensure_cancel_schema(conn)
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
            active = str(row["job_id"]) if row and row["job_id"] else None
            if not active:
                return False
            if job_id is not None and job_id != active:
                return False
            conn.execute("UPDATE job_cancel SET requested = 1 WHERE id = 1")
            return True

    def cancel_requested(self) -> bool:
        with self._connect() as conn:
            self._ensure_cancel_schema(conn)
            row = conn.execute("SELECT requested FROM job_cancel WHERE id = 1").fetchone()
        return bool(row and int(row["requested"]) == 1)

    def force_release_job_lock(self) -> str | None:
        """Clear the job lock (e.g. after cancel). Returns previous job_id if any."""
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
            prev = str(row["job_id"]) if row and row["job_id"] else None
            conn.execute(
                """
                UPDATE job_lock SET
                    job_id = NULL, started_at = NULL,
                    pack = NULL, message = NULL, percent = 0, state = NULL
                WHERE id = 1
                """
            )
            self._ensure_cancel_schema(conn)
            conn.execute("UPDATE job_cancel SET requested = 0 WHERE id = 1")
            return prev

    def active_job(self) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
        if row and row["job_id"]:
            return str(row["job_id"])
        return None
