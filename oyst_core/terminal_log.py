"""Persistent session transcript for Settings Terminal / oyst-cli terminal."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from oyst_core.audit import redact_paths
from oyst_core.config import data_dir

Layer = Literal["structured", "raw"]
Source = Literal["cli", "rpc", "core"]

MAX_BYTES = 25 * 1024 * 1024
MAX_RAW_CHARS = 12 * 1024
ExportFormat = Literal["txt", "jsonl"]

# High-churn / self-referential methods — do not capture.
RPC_SKIP_METHODS = frozenset(
    {
        "job.status",
        "terminal.list",
        "terminal.clear",
        "terminal.export",
        "news.list",
        "config.get",
    },
)

_lock = threading.Lock()
_id_lock = threading.Lock()
_next_id: int | None = None


def transcript_path() -> Path:
    return data_dir() / "terminal.jsonl"


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_RAW_CHARS:
        return value[:MAX_RAW_CHARS] + "…[truncated]"
    if isinstance(value, dict):
        return {str(k): _truncate(v) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > 200:
            return [_truncate(v) for v in value[:200]] + ["…[truncated]"]
        return [_truncate(v) for v in value]
    return value


def _read_last_id(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            chunk = min(size, 8192)
            fh.seek(size - chunk)
            data = fh.read().decode("utf-8", errors="replace")
        for line in reversed(data.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "id" in obj:
                return int(obj["id"])
    except OSError:
        return 0
    return 0


def _alloc_id(path: Path) -> int:
    global _next_id
    with _id_lock:
        if _next_id is None:
            _next_id = _read_last_id(path)
        _next_id += 1
        return _next_id


def _strip_secrets(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        lk = str(key).lower()
        if lk in {"auth", "token", "password", "secret"} or "token" in lk:
            out[str(key)] = "<redacted>"
        elif isinstance(value, dict):
            out[str(key)] = _strip_secrets(value)
        else:
            out[str(key)] = value
    return out


def append(
    layer: Layer,
    source: Source,
    action: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one transcript line; trim ring if over MAX_BYTES."""
    path = transcript_path()
    safe_action = str(redact_paths(action))
    safe_message = str(redact_paths(message))
    safe_data: dict[str, Any] | None = None
    if data is not None:
        cleaned = _strip_secrets(data if isinstance(data, dict) else {"value": data})
        redacted = redact_paths(cleaned)
        if not isinstance(redacted, dict):
            redacted = {"value": redacted}
        truncated = _truncate(redacted)
        safe_data = truncated if isinstance(truncated, dict) else {"value": truncated}
    entry: dict[str, Any] = {
        "id": _alloc_id(path),
        "ts": _now_iso(),
        "layer": layer,
        "source": source,
        "action": safe_action,
        "message": safe_message,
    }
    if safe_data is not None:
        entry["data"] = safe_data
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        _chmod_private(path)
        if path.stat().st_size > MAX_BYTES:
            _trim_locked(path)
    return entry


def log_structured(
    source: Source,
    action: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    append("structured", source, action, message, data)


def log_raw(
    source: Source,
    action: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    append("raw", source, action, message, data)


def _trim_locked(path: Path) -> None:
    """Keep a suffix of complete JSONL lines under MAX_BYTES."""
    try:
        raw = path.read_bytes()
    except OSError:
        return
    if len(raw) <= MAX_BYTES:
        return
    # Keep last MAX_BYTES bytes, then advance to next newline.
    start = len(raw) - MAX_BYTES
    nl = raw.find(b"\n", start)
    if nl == -1:
        keep = raw[-MAX_BYTES:]
    else:
        keep = raw[nl + 1 :]
    tmp = path.with_suffix(".jsonl.tmp")
    try:
        tmp.write_bytes(keep)
        _chmod_private(tmp)
        tmp.replace(path)
        _chmod_private(path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def list_entries(
    limit: int = 500,
    *,
    since_id: int = 0,
    layers: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return up to ``limit`` entries in chronological order (oldest→newest)."""
    path = transcript_path()
    if not path.exists():
        return []
    limit = max(1, min(int(limit), 50_000))
    since_id = max(0, int(since_id))
    layer_set = {str(x) for x in layers} if layers else None
    matched: list[dict[str, Any]] = []
    with _lock:
        try:
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    eid = int(obj.get("id") or 0)
                    if eid <= since_id:
                        continue
                    if layer_set is not None and str(obj.get("layer")) not in layer_set:
                        continue
                    matched.append(obj)
        except OSError:
            return []
    if len(matched) > limit:
        return matched[-limit:]
    return matched


def clear() -> dict[str, Any]:
    path = transcript_path()
    with _lock:
        with _id_lock:
            global _next_id
            _next_id = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        _chmod_private(path)
    return {"ok": True, "cleared": True}


def _validate_export_target(path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    if any(ch in str(target) for ch in ("\n", "\r", "\0")):
        raise ValueError("export path contains control characters")
    exports = (data_dir() / "exports").resolve()
    exports.mkdir(parents=True, exist_ok=True)
    try:
        target.relative_to(exports)
    except ValueError as exc:
        raise ValueError(f"export path must be under {exports}") from exc
    return target


def _normalize_format(fmt: str) -> ExportFormat:
    cleaned = fmt.strip().lower().lstrip(".")
    if cleaned in {"txt", "text"}:
        return "txt"
    if cleaned in {"jsonl", "json"}:
        return "jsonl"
    raise ValueError(f"unsupported export format: {fmt} (use txt or jsonl)")


def format_entry_txt(entry: dict[str, Any]) -> str:
    ts = entry.get("ts") or ""
    layer = entry.get("layer") or ""
    source = entry.get("source") or ""
    action = entry.get("action") or ""
    message = entry.get("message") or ""
    prefix = f"[{ts}] [{layer}/{source}] {action}: {message}"
    data = entry.get("data")
    if data is not None:
        try:
            blob = json.dumps(data, ensure_ascii=False)
        except (TypeError, ValueError):
            blob = str(data)
        return f"{prefix} | {blob}"
    return prefix


def export(path: str | Path, *, fmt: str = "txt") -> dict[str, Any]:
    try:
        export_fmt = _normalize_format(fmt)
        target = _validate_export_target(path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if target.exists():
        return {"ok": False, "error": f"refusing to overwrite existing file: {target}"}
    entries = list_entries(limit=50_000)
    target.parent.mkdir(parents=True, exist_ok=True)
    if export_fmt == "jsonl":
        body = "".join(
            json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in entries
        )
    else:
        body = "\n".join(format_entry_txt(e) for e in entries) + ("\n" if entries else "")
    target.write_text(body, encoding="utf-8")
    _chmod_private(target)
    return {
        "ok": True,
        "path": str(target),
        "format": export_fmt,
        "count": len(entries),
    }


def log_rpc_call(method: str, params: dict[str, Any], *, ok: bool, result: Any = None) -> None:
    """Capture one RPC dispatch (structured + raw), skipping noisy methods."""
    if method in RPC_SKIP_METHODS:
        return
    try:
        status = "ok" if ok else "error"
        log_structured(
            "rpc",
            method,
            f"rpc {method} {status}",
            {"ok": ok},
        )
        raw_data: dict[str, Any] = {"params": params}
        if ok:
            raw_data["result"] = result
        else:
            raw_data["error"] = result
        log_raw("rpc", method, f"rpc {method} {status} (raw)", raw_data)
    except Exception:  # noqa: BLE001 — never break RPC for transcript
        pass


def reset_id_state_for_tests() -> None:
    """Test helper: forget cached id counter."""
    global _next_id
    with _id_lock:
        _next_id = None
