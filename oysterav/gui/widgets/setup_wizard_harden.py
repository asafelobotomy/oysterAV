"""Host hardening actions for the setup wizard."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.privilege import build_harden_plan
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.privilege_confirm import confirm_privilege_plan
from oysterav.gui.widgets.setup_wizard_harden_page import enabled_harden_step_ids

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def on_apply_harden(wizard: SetupWizard, *_args: object) -> None:
    if wizard._harden_busy:
        return
    step_ids = enabled_harden_step_ids(wizard)
    plan = build_harden_plan(["--preview"], step_ids=step_ids or ["harden"])
    confirm_privilege_plan(
        wizard.dialog,
        plan,
        on_continue=lambda: _run_apply_harden(wizard),
        continue_label="Continue",
    )


def _run_apply_harden(wizard: SetupWizard) -> None:
    wizard._harden_busy = True
    wizard.harden_label.set_text("Applying recommended host hardenings…")
    wizard._update_nav()
    enable_fw = wizard.enable_firewall_row.get_active()

    def worker() -> dict[str, Any]:
        return wizard.client.setup_run(
            skip_packs=True,
            skip_schedule=True,
            skip_bootstrap=True,
            skip_harden=False,
            enable_firewall=enable_fw,
            mark_complete=False,
            harden_include=enabled_harden_step_ids(wizard),
        )

    def done(result: dict[str, Any]) -> bool:
        wizard._harden_busy = False
        steps = [s for s in result.get("steps", []) if isinstance(s, dict)]
        harden_steps = [
            s
            for s in steps
            if str(s.get("step", "")).startswith("harden-") or s.get("step") == "firewall-ensure"
        ]
        ok_n = sum(1 for s in harden_steps if s.get("ok") or s.get("skipped"))
        soft = [s for s in harden_steps if s.get("soft_fail")]
        lines = [f"Hardenings finished ({ok_n}/{len(harden_steps)} OK)."]
        for step in soft[:4]:
            lines.append(f"  {step.get('step')}: {step.get('message', 'soft-failed')}")
        if not soft:
            lines.append("Prevention remains optional under Settings → Real-time.")
        wizard.harden_label.set_text("\n".join(lines))
        wizard._harden_ran = True
        wizard._refresh_ready_summary()
        wizard._update_nav()
        wizard._emit_changed()
        return False

    def fail(message: str) -> bool:
        wizard._harden_busy = False
        wizard.harden_label.set_text(f"Hardenings failed: {message}")
        wizard._update_nav()
        show_command_dialog(
            wizard.dialog,
            heading="Host hardenings failed",
            body=message,
            copy_text="oyst-cli setup run --skip-packs --skip-schedule --skip-bootstrap",
        )
        return False

    run_in_thread(worker, done, fail)
