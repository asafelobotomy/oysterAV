"""Auto-Install action for the setup wizard (privilege concert preflight)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.privilege import build_setup_plan
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.privilege_confirm import confirm_privilege_plan
from oysterav.gui.widgets.setup_wizard_actions import run_doctor
from oysterav.gui.widgets.setup_wizard_text import PAGE_TITLES

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def _recipe_labels(wizard: SetupWizard) -> list[tuple[str, str]]:
    switches = getattr(wizard, "auto_recipe_switches", {})
    labels: list[tuple[str, str]] = []
    mapping = [
        ("packs", "Install missing required and recommended packs"),
        ("linger", "Enable systemd user linger for scheduled scans"),
        ("schedule", "Install daily scheduled scan timer"),
        ("harden", "Apply recommended host hardenings"),
        ("firewall", "Enable host firewall (SSH-safe)"),
    ]
    for key, label in mapping:
        row = switches.get(key)
        if row is None or row.get_active():
            labels.append((key, label))
    return labels


def on_auto_install(wizard: SetupWizard, *_args: object) -> None:
    if wizard._auto_install_busy:
        return
    labels = _recipe_labels(wizard)
    plan = build_setup_plan(["--preview"], step_labels=labels or None)
    confirm_privilege_plan(
        wizard.dialog,
        plan,
        on_continue=lambda: _run_auto_install(wizard),
        continue_label="Continue",
    )


def _run_auto_install(wizard: SetupWizard) -> None:
    wizard._load_preferences()
    wizard._auto_install_busy = True
    wizard.welcome_status.set_text("Running Auto-Install with recommended defaults…")
    wizard._set_status("Running Auto-Install…")
    wizard._update_nav()
    auto_quarantine = wizard.auto_quarantine.get_active()
    switches = getattr(wizard, "auto_recipe_switches", {})

    def _on(key: str, default: bool = True) -> bool:
        row = switches.get(key)
        return default if row is None else bool(row.get_active())

    skip_packs = not _on("packs")
    skip_schedule = not _on("schedule")
    skip_harden = not _on("harden")
    enable_linger = _on("linger")
    enable_firewall = _on("firewall") and _on("harden", True)

    def worker() -> dict[str, Any]:
        return wizard.client.setup_run(
            confirm_aur=True,
            enable_linger=enable_linger,
            auto_quarantine=auto_quarantine,
            enable_firewall=enable_firewall,
            skip_packs=skip_packs,
            skip_schedule=skip_schedule,
            skip_harden=skip_harden,
        )

    def done(result: dict[str, Any]) -> bool:
        wizard._auto_install_busy = False
        completed = bool(result.get("completed"))
        ok = bool(result.get("ok"))
        steps_ok = result.get("steps_ok", 0)
        steps_total = result.get("steps_total", 0)
        if completed and ok:
            summary = f"Auto-Install finished ({steps_ok}/{steps_total} steps OK)."
            wizard.welcome_status.set_text(summary)
            wizard._set_status(summary)
            wizard._bootstrap_ran = True
            wizard._harden_ran = True
            wizard._refresh_schedule_status()
            run_doctor(wizard)
            wizard._go_to_page(len(PAGE_TITLES) - 1)
            wizard._emit_changed()
            if wizard._on_complete:
                wizard._on_complete()
        else:
            summary = f"Auto-Install finished with issues ({steps_ok}/{steps_total} steps OK)."
            wizard.welcome_status.set_text(summary)
            wizard._set_status(summary)
            body = summary
            failed = [
                step
                for step in result.get("steps", [])
                if isinstance(step, dict)
                and not step.get("ok")
                and not step.get("skipped")
                and not step.get("soft_fail")
            ]
            if failed:
                details = []
                for step in failed[:5]:
                    name = str(step.get("step", "?"))
                    message = str(step.get("message", "")).strip()
                    if message:
                        details.append(f"{name}: {message[:200]}")
                    else:
                        details.append(name)
                body = f"{summary}\n\n" + "\n".join(details)
            show_command_dialog(
                wizard.dialog,
                heading="Auto-Install completed with issues",
                body=body,
                copy_text="oyst-cli setup run --enable-linger",
            )
            wizard._refresh_schedule_status()
            run_doctor(wizard)
            wizard._emit_changed()
            if completed:
                wizard._bootstrap_ran = True
                wizard._harden_ran = True
                wizard._go_to_page(len(PAGE_TITLES) - 1)
                if wizard._on_complete:
                    wizard._on_complete()
            else:
                wizard._update_nav()
        return False

    def fail(message: str) -> bool:
        wizard._auto_install_busy = False
        wizard.welcome_status.set_text(f"Auto-Install failed: {message}")
        wizard._set_status(f"Auto-Install failed: {message}")
        wizard._update_nav()
        show_command_dialog(
            wizard.dialog,
            heading="Auto-Install failed",
            body=message,
            copy_text="oyst-cli setup run --enable-linger",
        )
        return False

    run_in_thread(worker, done, fail)


__all__ = ["on_auto_install"]
