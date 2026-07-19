"""One-shot runtime bootstrap (install + signatures + maintenance)."""

from __future__ import annotations

from typing import Any

from oyst_core.audit import SecurityAudit
from oyst_core.maintenance import run_bootstrap
from oyst_core.runtime.bootstrap import bootstrap_runtime, update_runtime
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.runtime.progress import ProgressCallback, emit_progress


def run_full_runtime_bootstrap(
    *,
    skip_install: bool = False,
    update_signatures: bool = True,
    run_maintenance: bool = True,
    skip_lynis: bool = True,
    on_progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Combined bootstrap matching GUI runtime_ui.bootstrap_runtime_from_gui."""
    if not is_full_mode():
        return {
            "ok": False,
            "message": "Runtime bootstrap requires full mode (runtime.mode=full)",
            "steps": [],
        }

    audit = SecurityAudit()
    steps: list[dict[str, Any]] = []

    if not skip_install:
        emit_progress(on_progress, "install", 0)

        def _install_progress(stage: str, percent: int) -> None:
            emit_progress(on_progress, stage, min(70, (percent * 70) // 100))

        install_results = bootstrap_runtime(
            on_progress=_install_progress if on_progress else None,
        )
        for entry in install_results:
            steps.append(
                {
                    "step": f"install-{entry.get('pack', '?')}",
                    "ok": bool(entry.get("ok")),
                    "message": entry.get("message", ""),
                },
            )
    else:
        steps.append({"step": "install", "ok": True, "skipped": True})

    if update_signatures:
        emit_progress(on_progress, "signatures", 75)
        update_res: dict[str, Any] = update_runtime()
        ok = bool(update_res.get("ok"))
        clamav = update_res.get("clamav", {})
        message = ""
        if isinstance(clamav, dict):
            message = str(clamav.get("message", ""))
        steps.append(
            {
                "step": "signatures",
                "ok": ok,
                "message": message,
            },
        )
    else:
        steps.append({"step": "signatures", "ok": True, "skipped": True})

    if run_maintenance:
        emit_progress(on_progress, "maintenance", 85)
        maint = run_bootstrap(skip_lynis=skip_lynis)
        ok_count = sum(1 for s in maint if s.get("ok"))
        steps.append(
            {
                "step": "maintenance",
                "ok": ok_count > 0,
                "message": f"Bootstrap {ok_count}/{len(maint)} steps OK",
                "details": maint,
            },
        )
    else:
        steps.append({"step": "maintenance", "ok": True, "skipped": True})

    ok_count = sum(1 for s in steps if s.get("ok"))
    success = ok_count > 0
    emit_progress(on_progress, "bootstrap", 100)
    result: dict[str, Any] = {
        "ok": success,
        "steps": steps,
        "steps_ok": ok_count,
        "steps_total": len(steps),
    }
    audit.log("runtime.bootstrap", "full", success=success, data={"steps_ok": ok_count})
    return result
