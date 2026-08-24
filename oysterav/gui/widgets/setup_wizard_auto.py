"""Auto-Install action for the setup wizard (privilege concert preflight)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from oyst_core.privilege import build_setup_plan
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.privilege_confirm import confirm_privilege_plan
from oysterav.gui.widgets.setup_wizard_actions import run_doctor
from oysterav.gui.widgets.setup_wizard_firewall import selected_firewall_backend
from oysterav.gui.widgets.setup_wizard_text import PAGE_TITLES

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def _recipe_labels(
    wizard: SetupWizard,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (privileged_labels, local_labels) for Auto-Install disclosure."""
    switches = getattr(wizard, "auto_recipe_switches", {})
    privileged: list[tuple[str, str]] = []
    local: list[tuple[str, str]] = []
    mapping = [
        ("packs", "Install missing required and recommended packs", True),
        ("linger", "Enable systemd user linger for scheduled scans", True),
        ("schedule", "Install daily scheduled scan timer", False),
        ("harden", "Apply recommended host hardenings", True),
        ("firewall", "Enable host firewall (SSH-safe)", True),
    ]
    for key, label, elevated in mapping:
        row = switches.get(key)
        if row is None or row.get_active():
            if elevated:
                privileged.append((key, label))
            else:
                local.append((key, label))
    return privileged, local


def on_auto_install(wizard: SetupWizard, *_args: object) -> None:
    if wizard._auto_install_busy:
        return
    privileged, local = _recipe_labels(wizard)
    plan = build_setup_plan(
        [],
        step_labels=privileged or None,
        local_step_labels=local or None,
        disclosure_only=True,
    )
    confirm_privilege_plan(
        wizard.dialog,
        plan,
        on_continue=lambda: _run_auto_install(wizard),
        continue_label="Continue",
    )


def _apply_ran_flags(wizard: SetupWizard, steps: list[dict[str, Any]]) -> None:
    """Set bootstrap/harden ran flags from successful step outcomes (UX-11)."""
    bootstrap_ok = False
    harden_ok = False
    for step in steps:
        name = str(step.get("step", ""))
        if step.get("ok") and name in {"maintenance-bootstrap", "signatures", "freshclam"}:
            bootstrap_ok = True
        details = step.get("details")
        if isinstance(details, list) and any(
            isinstance(d, dict) and d.get("step") == "freshclam" and d.get("ok") for d in details
        ):
            bootstrap_ok = True
        if step.get("ok") and (name.startswith("harden-") or name.startswith("firewall-")):
            harden_ok = True
    wizard._bootstrap_ran = bootstrap_ok
    wizard._harden_ran = harden_ok


def _issue_lines(steps: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for step in steps[:8]:
        name = str(step.get("step", "?"))
        message = str(step.get("message", "")).strip()
        tag = "soft" if step.get("soft_fail") else "fail"
        if message:
            lines.append(f"{name} ({tag}): {message[:200]}")
        else:
            lines.append(f"{name} ({tag})")
    return lines


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
    enable_firewall = _on("firewall")

    def worker() -> dict[str, Any]:
        backend = selected_firewall_backend(wizard) if enable_firewall else None
        result = wizard.client.setup_run(
            confirm_aur=True,
            skip_packs=skip_packs,
            skip_schedule=skip_schedule,
            skip_harden=skip_harden,
            enable_linger=enable_linger,
            enable_firewall=enable_firewall,
            firewall_backend=backend if enable_firewall else None,
            auto_quarantine=auto_quarantine,
            mark_complete=True,
        )
        if enable_firewall and backend:
            fw_ok = any(
                isinstance(s, dict)
                and s.get("step") in {"firewall-select", "firewall-ensure", "firewall-install"}
                and (s.get("ok") or s.get("skipped"))
                for s in (result.get("steps") or [])
            )
            select_steps = [
                s
                for s in (result.get("steps") or [])
                if isinstance(s, dict) and s.get("step") in {"firewall-select", "firewall-ensure"}
            ]
            if select_steps:
                fw_ok = all(s.get("ok") or s.get("skipped") for s in select_steps)
            if fw_ok or backend == "none":
                try:
                    wizard.client.config_set("firewall.managed_backend", backend)
                except Exception:
                    pass
        return result

    def done(result: dict[str, Any]) -> bool:
        wizard._auto_install_busy = False
        completed = bool(result.get("completed"))
        ok = bool(result.get("ok"))
        steps_ok = result.get("steps_ok", 0)
        steps_total = result.get("steps_total", 0)
        steps = [s for s in result.get("steps", []) if isinstance(s, dict)]
        soft_fails = [
            s for s in steps if s.get("soft_fail") and not s.get("ok") and not s.get("skipped")
        ]
        hard_fails = [
            s for s in steps if not s.get("ok") and not s.get("skipped") and not s.get("soft_fail")
        ]
        _apply_ran_flags(wizard, steps)
        pure_success = completed and ok and not soft_fails
        if pure_success:
            summary = f"Auto-Install finished ({steps_ok}/{steps_total} steps OK)."
            wizard.welcome_status.set_text(summary)
            wizard._set_status(summary)
            wizard._refresh_schedule_status()
            run_doctor(wizard)
            wizard._go_to_page(len(PAGE_TITLES) - 1)
            wizard._emit_changed()
            if wizard._on_complete:
                wizard._on_complete()
            return False

        issues = soft_fails + hard_fails
        if completed and soft_fails and not hard_fails:
            summary = f"Auto-Install completed with warnings ({steps_ok}/{steps_total} steps OK)."
            heading = "Auto-Install completed with warnings"
        else:
            summary = f"Auto-Install finished with issues ({steps_ok}/{steps_total} steps OK)."
            heading = "Auto-Install completed with issues"
        wizard.welcome_status.set_text(summary)
        wizard._set_status(summary)
        body = summary
        if issues:
            body = f"{summary}\n\n" + "\n".join(_issue_lines(issues))
        show_command_dialog(
            wizard.dialog,
            heading=heading,
            body=body,
            copy_text="oyst-cli setup run --enable-linger",
        )
        wizard._refresh_schedule_status()
        run_doctor(wizard)
        wizard._emit_changed()
        if completed:
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
