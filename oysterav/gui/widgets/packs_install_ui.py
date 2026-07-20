"""Pack install / remove / refresh helpers for PackListWidget."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.progress_button import run_progress_button


class _PackListHost(Protocol):
    client: OystClient
    _on_changed: Callable[[], None] | None

    def _dialog_window(self) -> Gtk.Window | None: ...

    def _set_status(self, text: str) -> None: ...

    def set_packs(
        self,
        packs: list[dict[str, Any]],
        *,
        runtime: dict[str, Any] | None = None,
    ) -> None: ...


def on_install_clicked(widget: _PackListHost, button: Gtk.Button, name: str) -> None:
    start_install(widget, button, name, confirm_aur=False)


def on_runtime_install_clicked(widget: _PackListHost, button: Gtk.Button, name: str) -> None:
    idle = button.get_label() or "Install to runtime"
    widget._set_status(f"Installing {name}…")

    def worker(report: Callable[[int], None]) -> dict[str, Any]:
        def on_progress(_stage: str, percent: int) -> None:
            report(percent)

        result = widget.client.runtime_install(name, on_progress=on_progress)
        return dict(result) if isinstance(result, dict) else {"ok": False}

    def done(result: dict[str, Any]) -> None:
        if result.get("ok"):
            widget._set_status(f"{name}: {result.get('message', 'installed')}")
            refresh_packs(widget)
            return
        message = str(result.get("message") or "Install failed")
        widget._set_status(f"Install {name}: {message}")
        show_command_dialog(
            widget._dialog_window(),
            heading=f"Install {name}",
            body=message,
            copy_text=message,
        )

    def fail(msg: str) -> None:
        widget._set_status(f"Install failed: {msg}")
        show_command_dialog(
            widget._dialog_window(),
            heading=f"Install {name}",
            body=msg,
            copy_text=msg,
        )

    run_progress_button(
        button,
        worker,
        busy_verb="Installing",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


def on_remove_clicked(
    widget: _PackListHost,
    _btn: Gtk.Button,
    name: str,
    button: Gtk.Button,
) -> None:
    idle = button.get_label() or "Remove"
    widget._set_status(f"Removing {name}…")

    def worker(report: Callable[[int], None]) -> dict[str, Any]:
        def on_progress(_stage: str, percent: int) -> None:
            report(percent)

        return widget.client.runtime_remove(name, on_progress=on_progress)

    def done(result: dict[str, Any]) -> None:
        widget._set_status(str(result.get("message", f"Removed {name}")))
        refresh_packs(widget)

    def fail(msg: str) -> None:
        widget._set_status(f"Remove failed: {msg}")

    run_progress_button(
        button,
        worker,
        busy_verb="Removing",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


def start_install(
    widget: _PackListHost,
    button: Gtk.Button,
    name: str,
    *,
    confirm_aur: bool,
) -> None:
    idle = button.get_label() or "Install"
    widget._set_status(f"Installing {name}…")

    def worker(report: Callable[[int], None]) -> dict[str, Any]:
        def on_progress(_stage: str, percent: int) -> None:
            report(percent)

        return widget.client.pack_install(
            name,
            confirm_aur=confirm_aur,
            on_progress=on_progress,
        )

    def done(result: dict[str, Any]) -> None:
        mode = result.get("mode", "")
        if mode == "aur_confirm" and not confirm_aur:
            confirm_aur_install(widget, button, name, result)
            return
        if result.get("ok"):
            widget._set_status(f"{name} installed")
            refresh_packs(widget)
            return
        show_install_failure(widget, name, result)

    def fail(msg: str) -> None:
        widget._set_status(f"Install failed: {msg}")

    run_progress_button(
        button,
        worker,
        busy_verb="Installing",
        idle_label=idle,
        on_success=done,
        on_error=fail,
    )


def confirm_aur_install(
    widget: _PackListHost,
    button: Gtk.Button,
    name: str,
    preview: dict[str, Any],
) -> None:
    hint = str(preview.get("install_hint", ""))
    message = str(preview.get("message", f"{name} requires an AUR install"))
    dialog = Adw.MessageDialog(
        transient_for=widget._dialog_window(),
        heading=f"Install {name} from AUR?",
        body=f"{message}\n\nThis will run:\n{hint}",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("install", "Install from AUR")
    dialog.set_default_response("install")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "install":
            start_install(widget, button, name, confirm_aur=True)

    dialog.connect("response", on_response)
    dialog.present()


def show_install_failure(widget: _PackListHost, name: str, result: dict[str, Any]) -> None:
    mode = result.get("mode", "")
    hint = str(result.get("install_hint", ""))
    message = str(result.get("message", "Install failed"))
    reason = str(result.get("reason", ""))
    if reason == "aur_confirmation_required":
        return
    if mode in ("command", "manual", "aur") and hint:
        show_command_dialog(
            widget._dialog_window(),
            heading=f"Install {name}",
            body=f"{message}\n\nRun in a terminal:\n{hint}",
            copy_text=hint,
        )
    else:
        widget._set_status(f"Install {name}: {message}")


def refresh_packs(widget: _PackListHost) -> None:
    def load() -> dict[str, Any]:
        return {
            "packs": widget.client.doctor(),
            "runtime": widget.client.runtime_status(),
        }

    def done(data: dict[str, Any]) -> bool:
        packs_raw = data.get("packs")
        packs = packs_raw if isinstance(packs_raw, list) else []
        runtime_raw = data.get("runtime")
        runtime = runtime_raw if isinstance(runtime_raw, dict) else {}
        widget.set_packs(list(packs), runtime=runtime)
        if widget._on_changed:
            widget._on_changed()
        return False

    run_in_thread(load, done, lambda _m: False)
