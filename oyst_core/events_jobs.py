"""EventLog mixin: job lock, progress, and cancel."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Any

_JOB_CANCEL_DDL = (
    "CREATE TABLE IF NOT EXISTS job_cancel ("
    "id INTEGER PRIMARY KEY CHECK (id = 1), "
    "requested INTEGER NOT NULL)"
)

# Worker died without release_job_lock (kill/crash/reboot): no heartbeat for this long.
# Live jobs refresh ``heartbeat_at`` via set_job_progress / touch_job_heartbeat, so
# legitimately long scans (up to the 7200s RPC timeout) are never judged stale.
STALE_JOB_HEARTBEAT = timedelta(minutes=10)

_CLEAR_LOCK_SQL = """
    UPDATE job_lock SET
        job_id = NULL, started_at = NULL, heartbeat_at = NULL,
        pack = NULL, message = NULL, percent = 0, state = NULL
    WHERE id = 1
"""


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
        if "heartbeat_at" not in cols:
            conn.execute("ALTER TABLE job_lock ADD COLUMN heartbeat_at TEXT")

    def _release_owned(
        self,
        conn: sqlite3.Connection,
        job_id: str,
        *,
        match_beat: bool = False,
        beat: Any = None,
    ) -> bool:
        """Clear the lock only if ``job_id`` still owns it; reset cancel in the same txn."""
        sql = _CLEAR_LOCK_SQL + " AND job_id = ?"
        params: tuple[Any, ...] = (job_id,)
        if match_beat:
            sql += " AND heartbeat_at IS ?"
            params = (job_id, beat)
        if conn.execute(sql, params).rowcount != 1:
            return False
        self._ensure_cancel_schema(conn)
        conn.execute("UPDATE job_cancel SET requested = 0 WHERE id = 1")
        return True

    def acquire_job_lock(self, job_id: str) -> bool:
        self.clear_stale_job_lock()
        now = datetime.now().isoformat()
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            # Single conditional UPDATE: SQLite serialises writers, so only one
            # process can flip job_id from NULL (no SELECT-then-UPDATE race).
            cur = conn.execute(
                """
                UPDATE job_lock SET
                    job_id = ?, started_at = ?, heartbeat_at = ?,
                    pack = NULL, message = 'Starting', percent = 0, state = 'running'
                WHERE id = 1 AND job_id IS NULL
                """,
                (job_id, now, now),
            )
            if cur.rowcount != 1:
                return False
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
                    pack = ?, message = ?, percent = ?, state = ?, heartbeat_at = ?
                WHERE id = 1 AND job_id = ?
                """,
                (
                    pack or None,
                    message or None,
                    float(percent),
                    state,
                    datetime.now().isoformat(),
                    job_id,
                ),
            )

    def touch_job_heartbeat(self, job_id: str) -> bool:
        """Refresh the liveness timestamp. False once ``job_id`` no longer owns the lock."""
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            cur = conn.execute(
                "UPDATE job_lock SET heartbeat_at = ? WHERE id = 1 AND job_id = ?",
                (datetime.now().isoformat(), job_id),
            )
            return cur.rowcount == 1

    def get_job_progress(self) -> dict[str, Any]:
        self.clear_stale_job_lock()
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
            self._release_owned(conn, job_id)

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
        """Clear the job lock (explicit user recovery). Returns previous job_id if any."""
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
            prev = str(row["job_id"]) if row and row["job_id"] else None
            conn.execute(_CLEAR_LOCK_SQL)
            self._ensure_cancel_schema(conn)
            conn.execute("UPDATE job_cancel SET requested = 0 WHERE id = 1")
            return prev

    def clear_stale_job_lock(self) -> str | None:
        """Drop zombie locks whose worker stopped heartbeating (kill/crash/reboot)."""
        with self._connect() as conn:
            self._ensure_job_progress_schema(conn)
            row = conn.execute("SELECT * FROM job_lock WHERE id = 1").fetchone()
            if row is None or not row["job_id"]:
                return None
            job_id = str(row["job_id"])
            beat = row["heartbeat_at"]
            last_raw = beat or row["started_at"]
            try:
                last = datetime.fromisoformat(str(last_raw)) if last_raw else None
            except ValueError:
                last = None
            if last is not None and datetime.now() - last < STALE_JOB_HEARTBEAT:
                return None
            # Conditional on the exact row we judged stale: never clobber a lock that
            # was refreshed or re-acquired by another job in the meantime.
            return job_id if self._release_owned(conn, job_id, match_beat=True, beat=beat) else None

    def active_job(self) -> str | None:
        self.clear_stale_job_lock()
        with self._connect() as conn:
            row = conn.execute("SELECT job_id FROM job_lock WHERE id = 1").fetchone()
        if row and row["job_id"]:
            return str(row["job_id"])
        return None
