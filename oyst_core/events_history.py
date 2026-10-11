"""EventLog mixin: scan history and finding patches."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from oyst_core.audit import redact_paths
from oyst_core.finding_status import open_findings_count, scan_is_clean


class EventHistoryMixin:
    """Scan history / finding patch methods for EventLog."""

    db_path: Any

    def _connect(self) -> sqlite3.Connection:
        raise NotImplementedError

    def log(self, kind: str, message: str, data: dict[str, Any] | None = None) -> None:
        payload = redact_paths(data or {})
        safe_message = str(redact_paths(message))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (ts, kind, message, data) VALUES (?, ?, ?, ?)",
                (datetime.now().isoformat(), kind, safe_message, json.dumps(payload)),
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

    @staticmethod
    def _scan_row(result: dict[str, Any]) -> tuple[Any, ...]:
        return (
            result["job_id"],
            result["profile"],
            json.dumps(result.get("paths", [])),
            result["started_at"],
            result.get("finished_at"),
            1 if result.get("clean", True) else 0,
            len(result.get("findings", [])),
            json.dumps(result),
        )

    def save_scan(self, result: dict[str, Any]) -> None:
        """Persist a scan; re-saving is only allowed for the same run (same started_at).

        A different scan reusing an existing job_id raises ValueError instead of
        silently overwriting that scan's history.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_history (
                    job_id, profile, paths, started_at, finished_at,
                    clean, findings_count, result_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    profile = excluded.profile, paths = excluded.paths,
                    finished_at = excluded.finished_at, clean = excluded.clean,
                    findings_count = excluded.findings_count,
                    result_json = excluded.result_json
                WHERE scan_history.started_at = excluded.started_at
                """,
                self._scan_row(result),
            )
            if cur.rowcount == 0:
                raise ValueError(f"scan history already exists for job_id: {result['job_id']}")

    @staticmethod
    def _apply_finding_patch(
        findings: list[Any],
        key: tuple[str, str, str, str],
        *,
        quarantined: bool | None,
        resolved: bool | None,
    ) -> bool:
        fields = ("pack", "path", "threat_name", "message")
        # Exact match first, then without message (parsers may differ slightly).
        for width in (4, 3):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                if all(str(finding.get(f) or "") == key[i] for i, f in enumerate(fields[:width])):
                    if quarantined is not None:
                        finding["quarantined"] = quarantined
                    if resolved is not None:
                        finding["resolved"] = resolved
                    return True
        return False

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
        """Update flags on one finding in a stored scan; recompute clean.

        Read-modify-write runs in one BEGIN IMMEDIATE transaction so concurrent
        patches on the same scan serialise instead of losing updates.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT result_json FROM scan_history WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            result: Any = None
            if row is not None and isinstance(row["result_json"], str):
                try:
                    result = json.loads(row["result_json"])
                except json.JSONDecodeError:
                    result = None
            if not isinstance(result, dict):
                return {"ok": False, "error": f"scan not found: {job_id}"}
            findings = result.get("findings")
            if not isinstance(findings, list):
                return {"ok": False, "error": "scan has no findings list"}
            key = (pack, path, threat_name, message)
            if not self._apply_finding_patch(
                findings, key, quarantined=quarantined, resolved=resolved
            ):
                return {"ok": False, "error": "finding not found in scan"}
            result["findings"] = findings
            result["clean"] = scan_is_clean(findings, result.get("pack_errors"))
            conn.execute(
                """
                UPDATE scan_history SET clean = ?, findings_count = ?, result_json = ?
                WHERE job_id = ?
                """,
                (1 if result["clean"] else 0, len(findings), json.dumps(result), job_id),
            )
        return {"ok": True, "clean": result["clean"], "job_id": job_id}
