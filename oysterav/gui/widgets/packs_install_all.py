"""Install All for PackListWidget (full → runtime.install; lite → setup concert)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.privilege import (
    build_install_packs_plan,
    preflight_body,
    sort_pack_names,
)
from oysterav.gui.widgets.common import show_command_dialog
from oysterav.gui.widgets.packs_install_ui import refresh_packs
from oysterav.gui.widgets.progress_button import run_progress_button


class _PackListHost(Protocol):
    client: OystClient
    _full_mode: bool
    _packs: list[dict[str, Any]]
    _on_changed: Callable[[], None] | None
    install_all_btn: Gtk.Button
    install_all_switches: dict[str, Adw.SwitchRow]

    def _dialog_window(self) -> Gtk.Window | None: ...

    def _set_status(self, text: str) -> None: ...

    def set_packs(
        self,
        packs: list[dict[str, Any]],
        *,
        runtime: dict[str, Any] | None = None,
    ) -> None: ...


def missing_pack_names(packs: list[dict[str, Any]]) -> list[str]:
    names = [
        str(p.get("name") or "")
        for p in packs
        if str(p.get("name") or "") and not p.get("installed")
    ]
    tiers = {
        str(p.get("name") or ""): str(p.get("tier") or "")
        for p in packs
        if str(p.get("name") or "")
    }
    return sort_pack_names(names, tiers=tiers)


def selected_missing_packs(widget: _PackListHost) -> list[str]:
    missing = missing_pack_names(widget._packs)
    switches = getattr(widget, "install_all_switches", {})
    if not switches:
        return missing
    return [n for n in missing if switches.get(n) is None or switches[n].get_active()]


def on_install_all_clicked(widget: _PackListHost, *_args: object) -> None:
    names = selected_missing_packs(widget)
    if not names:
        widget._set_status("No missing packs to install")
        return
    tiers = {
        str(p.get("name") or ""): str(p.get("tier") or "")
        for p in widget._packs
        if str(p.get("name") or "")
    }
    elevate = not widget._full_mode
    plan = build_install_packs_plan(names, tiers=tiers, elevate=elevate)
    body = (
        preflight_body(plan)
        if plan.needs_elevation or plan.local_steps
        else ("Install selected packs into the private runtime.")
    )
    dialog = Adw.MessageDialog(
        transient_for=widget._dialog_window(),
        heading=plan.title,
        body=body,
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("install", "Install All")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("install", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "install":
            return
        if widget._full_mode:
            _run_runtime_install_all(widget, names)
        else:
            _run_lite_install_all(widget, names)

    dialog.connect("response", on_response)
    dialog.present()


def _run_runtime_install_all(widget: _PackListHost, names: list[str]) -> None:
    btn = widget.install_all_btn
    idle = btn.get_label() or "Install All"
    widget._set_status("Installing selected runtime packs…")
    copy_hint = "oyst-cli runtime install " + " ".join(names[:3]) + (" …" if len(names) > 3 else "")

    def worker(report: Callable[[int], None]) -> dict[str, Any]:
        def on_progress(_stage: str, percent: int) -> None:
            report(percent)

        result = widget.client.runtime_install(packs=names, on_progress=on_progress)
        return dict(result) if isinstance(result, dict) else {"ok": False}

    def done(result: dict[str, Any]) -> None:
        msg = str(result.get("message") or ("Installed" if result.get("ok") else "Install failed"))
        widget._set_status(msg)
        if not result.get("ok"):
            show_command_dialog(
                widget._dialog_window(),
                heading="Install All",
                body=msg,
                copy_text=copy_hint,
            )
        refresh_packs(widget)

    def fail(msg: str) -> None:
        widget._set_status(f"Install All failed: {msg}")
        show_command_dialog(
            widget._dialog_window(),
            heading="Install All",
            body=msg,
            copy_text=copy_hint,
        )

    run_progress_button(
        btn,
        worker,
        busy_verb="Installing",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


def _run_lite_install_all(widget: _PackListHost, names: list[str]) -> None:
    btn = widget.install_all_btn
    idle = btn.get_label() or "Install All"
    widget._set_status("Installing packs (one authentication)…")

    def worker(report: Callable[[int], None]) -> dict[str, Any]:
        _ = report
        return widget.client.setup_run(
            packs=names,
            confirm_aur=True,
            skip_harden=True,
            skip_schedule=True,
            skip_bootstrap=True,
            enable_firewall=False,
            enable_linger=False,
            mark_complete=False,
        )

    def done(result: dict[str, Any]) -> None:
        ok = bool(result.get("ok"))
        steps_ok = result.get("steps_ok", 0)
        steps_total = result.get("steps_total", 0)
        msg = f"Install All finished ({steps_ok}/{steps_total} steps OK)"
        widget._set_status(msg)
        if not ok:
            show_command_dialog(
                widget._dialog_window(),
                heading="Install All",
                body=msg,
                copy_text="oyst-cli packs install <name>",
            )
        refresh_packs(widget)

    def fail(msg: str) -> None:
        widget._set_status(f"Install All failed: {msg}")
        show_command_dialog(
            widget._dialog_window(),
            heading="Install All",
            body=msg,
            copy_text="oyst-cli packs install <name>",
        )

    run_progress_button(
        btn,
        worker,
        busy_verb="Installing",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


__all__ = [
    "missing_pack_names",
    "on_install_all_clicked",
    "selected_missing_packs",
]
