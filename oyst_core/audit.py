"""Security audit trail for privileged and sensitive operations."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from oyst_core.config import data_dir

AUDIT_KINDS = frozenset(
    {
        "pack.install",
        "quarantine.restore",
        "quarantine.delete",
        "config.set",
        "schedule.install",
        "schedule.enable_linger",
        "schedule.disable_linger",
        "helper.install",
        "auth.grant",
        "auth.revoke",
        "privileged.run",
        "setup.run",
        "setup.harden",
        "setup.concert",
        "runtime.bootstrap",
        "firewall.mutate",
        "fail2ban.unban",
        "fail2ban.jail",
        "clamav.clamd",
        "clamav.virusevent",
        "clamav.ensure_virusevent",
        "clamav.ensure_disable_cache",
        "clamonacc.ensure_fdpass",
        "clamonacc.ensure_prevention",
        "maldet.monitor",
        "lynis.audit",
    },
)

_PATH_REDACT_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"/home/[^/\s\"']+"), "/home/<redacted>"),
    (re.compile(r"/var/home/[^/\s\"']+"), "/var/home/<redacted>"),
    (re.compile(r"/run/user/\d+"), "/run/user/<redacted>"),
    (re.compile(r"/tmp/oysterav-[^/\s\"']+"), "/tmp/oysterav-<redacted>"),
    (re.compile(r"/var/tmp/oysterav-[^/\s\"']+"), "/var/tmp/oysterav-<redacted>"),
)


def redact_paths(value: Any) -> Any:
    """Redact user path prefixes in nested data (home, XDG runtime, oysterAV tmp)."""
    if isinstance(value, str):
        text = value
        for pattern, repl in _PATH_REDACT_RULES:
            text = pattern.sub(repl, text)
        return text
    if isinstance(value, dict):
        return {str(k): redact_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_paths(v) for v in value]
    return value


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class SecurityAudit:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or (data_dir() / "events.db")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        _chmod_private(self.db_path)
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    action TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    data TEXT
                )
                """,
            )
        _chmod_private(self.db_path)

    def log(
        self,
        kind: str,
        action: str,
        *,
        success: bool = True,
        data: dict[str, Any] | None = None,
    ) -> None:
        safe_action = str(redact_paths(action))
        safe_data = redact_paths(data or {})
        if not isinstance(safe_data, dict):
            safe_data = {"value": safe_data}
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO security_audit (ts, kind, action, success, data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(),
                    kind,
                    safe_action,
                    1 if success else 0,
                    json.dumps(safe_data),
                ),
            )

    def list_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, ts, kind, action, success, data
                FROM security_audit
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            entry: dict[str, Any] = {
                "id": row["id"],
                "ts": row["ts"],
                "kind": row["kind"],
                "action": row["action"],
                "success": bool(row["success"]),
            }
            if row["data"]:
                try:
                    entry["data"] = json.loads(row["data"])
                except json.JSONDecodeError:
                    entry["data"] = {}
            else:
                entry["data"] = {}
            result.append(entry)
        return result
