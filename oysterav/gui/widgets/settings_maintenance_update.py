"""Update-all confirm + privilege disclosure for Settings → Maintenance."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oyst_core.privilege import build_update_all_plan, preflight_body
from oysterav.gui.rpc_actions import request_updates_apply
from oysterav.gui.widgets.common import run_in_thread

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def on_update_all(page: SettingsPage, *_args: object) -> None:
    page.update_all_btn.set_sensitive(False)
    page.maintenance_status_row.set_subtitle("Checking updates…")

    def load() -> dict[str, Any]:
        check = page.client.updates_check()
        return dict(check) if isinstance(check, dict) else {"updates": []}

    def done(check: dict[str, Any]) -> bool:
        page.update_all_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle("Ready")
        updates_raw = check.get("updates") or []
        updates = [u for u in updates_raw if isinstance(u, dict)]
        pkg_names = [
            str(u.get("package") or u.get("name") or "")
            for u in updates
            if str(u.get("package") or u.get("name") or "")
        ]
        plan = build_update_all_plan(
            package_names=pkg_names,
            needs_package_elevation=bool(pkg_names),
        )
        dialog = Adw.MessageDialog(
            transient_for=page._window,
            heading=plan.title,
            body=preflight_body(plan),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("run", "Update all")
        dialog.set_response_appearance("run", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
            if response != "run":
                return
            _run_update_all(page)

        dialog.connect("response", on_response)
        dialog.present()
        return False

    def fail(message: str) -> bool:
        page.update_all_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"Update check failed: {message}")
        return False

    run_in_thread(load, done, fail)


def _run_update_all(page: SettingsPage) -> None:
    page.update_all_btn.set_sensitive(False)
    page.maintenance_status_row.set_subtitle("Running Update all…")
    page._set_status("Running Update all…")

    def done(result: dict[str, Any]) -> bool:
        page.update_all_btn.set_sensitive(True)
        raw_steps = result.get("steps")
        steps: list[Any] = list(raw_steps) if isinstance(raw_steps, list) else []
        ok_count = sum(1 for s in steps if isinstance(s, dict) and s.get("ok"))
        msg = str(
            result.get("message") or f"Update all finished ({ok_count}/{len(steps)} OK)",
        )
        page.maintenance_status_row.set_subtitle(msg)
        page._set_status(msg)
        if page._on_updates_changed:
            page._on_updates_changed()
        from oysterav.gui.widgets.settings_maintenance_ui import reload_security_packs

        reload_security_packs(page)
        return False

    def fail(message: str) -> bool:
        page.update_all_btn.set_sensitive(True)
        page.maintenance_status_row.set_subtitle(f"Update all failed: {message}")
        page._set_status(f"Update all failed: {message}")
        if page._on_updates_changed:
            page._on_updates_changed()
        return False

    run_in_thread(lambda: request_updates_apply(page.client), done, fail)


__all__ = ["on_update_all"]
