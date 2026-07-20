"""SQLite event log and scan history."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from oyst_core.config import data_dir
from oyst_core.events_history import EventHistoryMixin
from oyst_core.events_jobs import EventJobsMixin


class EventLog(EventHistoryMixin, EventJobsMixin):
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (data_dir() / "events.db")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

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
