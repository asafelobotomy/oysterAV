"""EventLog mixin: job lock, progress, and cancel."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any

_JOB_CANCEL_DDL = (
    "CREATE TABLE IF NOT EXISTS job_cancel ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "requested INTEGER NOT NULL)"
)


class EventJobsMixin:
    """Job lock / progress / cancel methods for EventLog."""

    db_path: Any

    def _connect(self) -> sqlite3.Connection:
        raise NotImplementedError

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
