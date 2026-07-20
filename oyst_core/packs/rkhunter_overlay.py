"""Merge/apply rkhunter whitelist overlay and resolve findings."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from oyst_core.packs.rkhunter_resolve_plan import (
    _SINGLE_VALUE_OPTIONS,
    OVERLAY_HEADER,
    OVERLAY_PATH,
    ResolvePlan,
    path_allowed_for_resolve,
    plan_resolve,
    validate_whitelist_option,
)
from oyst_core.privileged.helper import run_privileged_helper


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
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o644)
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
    planned: list[tuple[dict[str, object], ResolvePlan]] = []
    errors: list[str] = []

    for raw in findings:
        threat = str(raw.get("threat_name") or "")
        path = str(raw.get("path") or "")
        message = str(raw.get("message") or "")
        try:
            plan = plan_resolve(threat, path=path, message=message)
            if plan.requires_path:
                path_allowed_for_resolve(plan.value, plan.threat_name, force=force)
        except ValueError as exc:
            errors.append(f"{threat or path or 'finding'}: {exc}")
            continue
        planned.append((raw, plan))

    items: list[dict[str, object]] = []
    for raw, plan in planned:
        items.append(
            {
                "ok": True,
                "threat_name": plan.threat_name,
                "path": str(raw.get("path") or ""),
                "message": str(raw.get("message") or ""),
                "option": plan.option,
                "value": plan.value,
                "explanation": plan.explanation,
                "overlay": str(OVERLAY_PATH),
            }
        )

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

    if not planned:
        return {
            "ok": len(errors) == 0,
            "resolved": 0,
            "errors": errors,
            "items": [],
        }

    directives: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for _, plan in planned:
        key = (plan.option, plan.value)
        if key in seen:
            continue
        seen.add(key)
        directives.append(key)

    argv = ["set-many", *[f"{opt}={val}" for opt, val in directives]]
    res = run_privileged_helper("rkhunter-whitelist", argv, timeout=60)
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "rkhunter-whitelist set-many failed").strip()
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

    message = (res.stdout or "").strip() or "whitelist updated"
    for item in items:
        item["changed"] = True
        item["message"] = message
    return {
        "ok": len(errors) == 0,
        "resolved": len(items),
        "errors": errors,
        "items": items,
    }
