"""Runtime bootstrap UI for setup wizard and settings."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import dialog_parent, run_in_thread, show_command_dialog
from oysterav.gui.widgets.progress_button import run_progress_button


def _format_disk(bytes_val: int) -> str:
    mb = bytes_val // (1024 * 1024)
    if mb < 1024:
        return f"{mb} MB"
    return f"{mb / 1024:.1f} GB"


def format_runtime_status_line(status: dict[str, Any]) -> str:
    disk_bytes = int(status.get("disk_bytes", 0) or 0)
    mode = status.get("mode", "?")
    return f"Mode: {mode} · Disk: {_format_disk(disk_bytes)}"


def bootstrap_steps(result: dict[str, Any]) -> list[dict[str, Any]]:
    steps = result.get("steps", [])
    if not isinstance(steps, list):
        return []
    return [
        {
            "step": str(step.get("step", "?")),
            "ok": bool(step.get("ok")),
            "message": str(step.get("message", "")),
            "skipped": bool(step.get("skipped", False)),
        }
        for step in steps
        if isinstance(step, dict)
    ]


def bootstrap_runtime_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[list[dict[str, Any]]], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    update_signatures: bool = False,
    run_maintenance: bool = False,
    skip_install: bool = False,
    progress_button: Gtk.Button | None = None,
    progress_verb: str = "Installing",
) -> None:
    dialog_win = dialog_parent(window, parent)
    if on_status:
        on_status("Running runtime bootstrap…")

    idle_label = progress_button.get_label() if progress_button is not None else None

    def worker(report: Callable[[int], None] | None = None) -> list[dict[str, Any]]:
        def on_progress(_stage: str, percent: int) -> None:
            if report:
                report(percent)

        result = client.runtime_bootstrap(
            skip_install=skip_install,
            update_signatures=update_signatures,
            run_maintenance=run_maintenance,
            on_progress=on_progress if progress_button is not None else None,
        )
        return bootstrap_steps(result)

    def done(results: list[dict[str, Any]]) -> bool:
        if progress_button is not None:
            progress_button.set_sensitive(True)
            if idle_label is not None:
                progress_button.set_label(idle_label)
        ok_count = sum(1 for r in results if r.get("ok"))
        if on_status:
            on_status(f"Runtime bootstrap finished ({ok_count}/{len(results)} OK)")
        if on_complete:
            on_complete(results)
        failed = [r for r in results if not r.get("ok")]
        if failed and dialog_win:
            lines = "\n".join(
                f"{f.get('step', '?')}: {f.get('message', 'failed')}" for f in failed[:5]
            )
            show_command_dialog(
                dialog_win,
                heading="Some runtime bootstrap steps failed",
                body=lines,
                copy_text="oyst-cli runtime bootstrap",
            )
        return False

    def fail(message: str) -> bool:
        if progress_button is not None:
            progress_button.set_sensitive(True)
            if idle_label is not None:
                progress_button.set_label(idle_label)
        if on_error:
            on_error(message)
        elif on_status:
            on_status(f"Runtime failed: {message}")
        return False

    if progress_button is not None:

        def _on_success(results: Any) -> None:
            done(results)

        def _on_error(message: str) -> None:
            fail(message)

        run_progress_button(
            progress_button,
            worker,
            busy_verb=progress_verb,
            idle_label=idle_label,
            on_success=_on_success,
            on_error=_on_error,
        )
        return

    run_in_thread(worker, done, fail)


def refresh_runtime_status_label(
    client: OystClient,
    row: Adw.ActionRow,
    *,
    action_button: Gtk.Button | None = None,
) -> None:
    def done(status: dict[str, Any]) -> bool:
        disk_bytes = int(status.get("disk_bytes", 0))
        disk = _format_disk(disk_bytes)
        mode = status.get("mode", "?")
        row.set_subtitle(f"Mode: {mode} · Disk: {disk}")
        if action_button is not None:
            action_button.set_label("Update…" if disk_bytes > 0 else "Install…")
        return False

    run_in_thread(client.runtime_status, done, lambda _m: False)
