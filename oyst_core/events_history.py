"""EventLog mixin: scan history and finding patches."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any

from oyst_core.finding_status import open_findings_count, scan_is_clean


class EventHistoryMixin:
    """Scan history / finding patch methods for EventLog."""

    db_path: Any

    def _connect(self) -> sqlite3.Connection:
        raise NotImplementedError

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
