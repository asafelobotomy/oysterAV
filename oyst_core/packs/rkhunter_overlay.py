"""Merge/apply rkhunter whitelist overlay and resolve findings."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from oyst_core.packs.rkhunter_resolve_plan import (
    _SINGLE_VALUE_OPTIONS,
    OVERLAY_HEADER,
    OVERLAY_PATH,
    validate_whitelist_option,
)
from oyst_core.packs.rkhunter_resolve_preview import collect_resolve_directives
from oyst_core.privilege.recipes import build_rkhunter_resolve_plan
from oyst_core.privilege.run import run_privilege_concert


def merge_overlay_text(existing: str, option: str, value: str) -> tuple[str, bool]:
    """Merge one directive into overlay text. Returns (new_text, changed)."""
    opt, val = validate_whitelist_option(option, value)
    line = f"{opt}={val}"
    lines = [ln.rstrip("\n") for ln in existing.splitlines() if ln.strip() != ""]
    if not lines or not lines[0].startswith("# oysterAV managed"):
        lines = [OVERLAY_HEADER.strip(), *lines]

    if opt in _SINGLE_VALUE_OPTIONS:
        out: list[str] = []
        replaced = False
        changed = False
        for ln in lines:
            if ln.startswith("#"):
                out.append(ln)
                continue
            if ln.startswith(f"{opt}="):
                if ln == line:
                    out.append(ln)
                    replaced = True
                else:
                    out.append(line)
                    replaced = True
                    changed = True
            else:
                out.append(ln)
        if not replaced:
            out.append(line)
            changed = True
        text = "\n".join(out) + "\n"
        return text, changed

    # multi-value: append if missing
    if line in lines:
        return "\n".join(lines) + "\n", False
    lines.append(line)
    return "\n".join(lines) + "\n", True


def apply_overlay_line(
    option: str,
    value: str,
    *,
    overlay_path: Path | None = None,
) -> dict[str, object]:
    """Write one directive into the oysterAV rkhunter overlay (caller must be root)."""
    result = apply_overlay_lines([(option, value)], overlay_path=overlay_path)
    applied = result.get("applied")
    first = applied[0] if isinstance(applied, list) and applied else {}
    return {
        "ok": True,
        "changed": bool(result.get("changed")),
        "option": first.get("option", option) if isinstance(first, dict) else option,
        "value": first.get("value", value) if isinstance(first, dict) else value,
        "overlay": result.get("overlay", str(OVERLAY_PATH)),
    }


def apply_overlay_lines(
    directives: Sequence[tuple[str, str]],
    *,
    overlay_path: Path | None = None,
) -> dict[str, object]:
    """Write many directives into the overlay in one file update (caller must be root)."""
    target = OVERLAY_PATH if overlay_path is None else overlay_path
    if not directives:
        return {
            "ok": True,
            "changed": False,
            "applied": [],
            "overlay": str(target),
        }
    existing = ""
    if target.is_file():
        existing = target.read_text(encoding="utf-8")
    changed_any = False
    applied: list[dict[str, object]] = []
    text = existing
    for option, value in directives:
        opt, val = validate_whitelist_option(option, value)
        text, changed = merge_overlay_text(text, opt, val)
        if changed:
            changed_any = True
        applied.append({"option": opt, "value": val, "changed": changed})
    if changed_any:
        from oyst_core.privileged.safe_write import write_text_nofollow

        target.parent.mkdir(parents=True, exist_ok=True)
        write_text_nofollow(target, text, mode=0o644)
    return {
        "ok": True,
        "changed": changed_any,
        "applied": applied,
        "overlay": str(target),
    }


def resolve_finding(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    """Plan and optionally apply a Resolve for one finding."""
    batch = resolve_findings_batch(
        [{"threat_name": threat_name, "path": path, "message": message}],
        force=force,
        dry_run=dry_run,
    )
    items = batch.get("items")
    first = items[0] if isinstance(items, list) and items else None
    if isinstance(first, dict):
        return first
    errors = batch.get("errors") or []
    err = errors[0] if isinstance(errors, list) and errors else "resolve failed"
    return {"ok": False, "error": str(err), "threat_name": threat_name}


def resolve_findings_batch(
    findings: Sequence[dict[str, object]],
    *,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    """Plan many findings, then apply all allowlisted directives in one privileged write.

    Path/ownership gates still run per finding before the helper is invoked.
    """
    directives, errors, items, _plans = collect_resolve_directives(findings, force=force)
    for item in items:
        item["overlay"] = str(OVERLAY_PATH)

    if dry_run:
        for item in items:
            item["dry_run"] = True
            item["changed"] = None
        return {
            "ok": len(errors) == 0,
            "resolved": len(items),
            "errors": errors,
            "items": items,
            "dry_run": True,
        }

    if not directives:
        return {
            "ok": len(errors) == 0,
            "resolved": 0,
            "errors": errors,
            "items": [],
        }

    priv = build_rkhunter_resolve_plan(directives)
    steps = run_privilege_concert(priv, timeout=60)
    failed = [s for s in steps if not s.get("ok")]
    if failed:
        err = str(failed[0].get("message") or "rkhunter-whitelist set-many failed").strip()
        for item in items:
            item["ok"] = False
            item["error"] = err
        errors.extend(f"{item.get('threat_name')}: {err}" for item in items)
        return {
            "ok": False,
            "resolved": 0,
            "errors": errors,
            "items": items,
        }

    message = "whitelist updated"
    for item in items:
        item["changed"] = True
        item["message"] = message
    return {
        "ok": len(errors) == 0,
        "resolved": len(items),
        "errors": errors,
        "items": items,
    }


# Re-export for callers that imported planning helpers from this module.
__all__ = [
    "apply_overlay_line",
    "apply_overlay_lines",
    "merge_overlay_text",
    "resolve_finding",
    "resolve_findings_batch",
]
