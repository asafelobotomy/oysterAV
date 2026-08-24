"""Schedule install and linger helpers for GUI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import dialog_parent, run_in_thread, show_command_dialog


def show_schedule_result(
    window: Gtk.Window | None,
    result: dict[str, Any],
    *,
    parent: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
    client: OystClient | None = None,
) -> None:
    _ = client  # retained for call-site compatibility
    parent_win = dialog_parent(window, parent)
    if on_complete:
        on_complete(result)
    if result.get("ok"):
        message = str(
            result.get("message")
            or ("Daily scan timer enabled" if result.get("enabled") else "Schedule timer updated")
        )
        if on_status:
            on_status(message)
        return

    hint = str(result.get("enable_hint", ""))
    message = str(result.get("message", "Timer install failed"))
    body = message
    if hint:
        body = f"{message}\n\nRun in a terminal:\n{hint}"
    show_command_dialog(
        parent_win,
        heading="Schedule timer",
        body=body,
        copy_text=hint or None,
    )
    if on_status:
        on_status("Schedule timer needs manual setup")


def _linger_is_off(status: dict[str, Any] | object) -> bool:
    return isinstance(status, dict) and status.get("linger") is False


def enable_linger_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
    on_failure: Callable[[], None] | None = None,
) -> None:
    parent_win = dialog_parent(window, parent)

    def done(result: dict[str, Any]) -> bool:
        if result.get("ok") or result.get("linger"):
            if on_status:
                on_status("Linger enabled for scheduled scans")
            if on_complete:
                on_complete()
        else:
            hint = ""
            linger = client.linger_status()
            if isinstance(linger, dict):
                hint = str(linger.get("enable_hint", ""))
            show_command_dialog(
                parent_win,
                heading="Enable linger",
                body=str(result.get("message", "Could not enable linger")),
                copy_text=hint or None,
            )
            if on_failure:
                on_failure()
        return False

    def fail(msg: str) -> bool:
        if on_status:
            on_status(f"Linger failed: {msg}")
        if on_failure:
            on_failure()
        return False

    run_in_thread(client.linger_enable, done, fail)


def _prompt_linger_and_apply(
    window: Gtk.Window | None,
    hint: str,
    *,
    client: OystClient,
    smoke_test: bool,
    on_status: Callable[[str], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
    on_cancel: Callable[[], None] | None = None,
    apply_worker: Callable[[], dict[str, Any]] | None = None,
) -> None:
    """One dialog: enable linger then apply schedule (no surprise post-apply prompt)."""
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Enable linger and apply schedule?",
        body=(
            "Scheduled scans need linger so timers keep running after logout.\n\n"
            "Enable linger (requires admin) and apply the schedule now, "
            "or copy the command for later."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("copy", "Copy command")
    dialog.add_response("enable", "Enable and apply")
    dialog.set_default_response("enable")
    dialog.set_response_appearance("enable", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "copy":
            clipboard = Gdk.Display.get_default().get_clipboard()
            clipboard.set(Gdk.ContentProvider.new_for_value(hint))
            if on_cancel:
                on_cancel()
        elif response == "enable":
            enable_linger_from_gui(
                client,
                window=window,
                on_status=on_status,
                on_complete=lambda: _run_schedule_apply(
                    client,
                    window=window,
                    smoke_test=smoke_test,
                    on_status=on_status,
                    on_error=on_error,
                    on_complete=on_complete,
                    apply_worker=apply_worker,
                ),
                on_failure=on_cancel,
            )
        elif on_cancel:
            on_cancel()

    dialog.connect("response", on_response)
    dialog.present()


def _run_schedule_apply(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    smoke_test: bool = False,
    on_status: Callable[[str], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
    apply_worker: Callable[[], dict[str, Any]] | None = None,
) -> None:
    parent_win = dialog_parent(window, parent)
    worker = apply_worker or (lambda: client.schedule_apply(smoke_test=smoke_test))

    def done(result: dict[str, Any]) -> bool:
        show_schedule_result(
            window,
            result,
            parent=parent_win,
            on_status=on_status,
            on_complete=on_complete,
            client=client,
        )
        return False

    def fail(msg: str) -> bool:
        if on_error:
            on_error(msg)
        elif on_status:
            on_status(f"Schedule apply failed: {msg}")
        return False

    run_in_thread(worker, done, fail)


def apply_schedule_timer(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    smoke_test: bool = False,
    prompt_linger: bool = True,
    on_status: Callable[[str], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
    on_cancel: Callable[[], None] | None = None,
    apply_worker: Callable[[], dict[str, Any]] | None = None,
) -> None:
    """Materialize systemd units; prompt once for linger before apply when needed."""
    parent_win = dialog_parent(window, parent)

    def run_apply() -> None:
        _run_schedule_apply(
            client,
            window=window,
            parent=parent_win,
            smoke_test=smoke_test,
            on_status=on_status,
            on_error=on_error,
            on_complete=on_complete,
            apply_worker=apply_worker,
        )

    if not prompt_linger:
        run_apply()
        return

    def after_linger_check(status: dict[str, Any]) -> bool:
        if _linger_is_off(status):
            _prompt_linger_and_apply(
                parent_win,
                str(status.get("enable_hint", "")),
                client=client,
                smoke_test=smoke_test,
                on_status=on_status,
                on_error=on_error,
                on_complete=on_complete,
                on_cancel=on_cancel,
                apply_worker=apply_worker,
            )
        else:
            run_apply()
        return False

    def fail(msg: str) -> bool:
        if on_error:
            on_error(msg)
        elif on_status:
            on_status(f"Schedule apply failed: {msg}")
        return False

    run_in_thread(client.linger_status, after_linger_check, fail)


def format_timer_status(status: dict[str, Any]) -> str:
    cal = str(status.get("on_calendar") or "").strip()
    config_raw = status.get("config")
    cfg = config_raw if isinstance(config_raw, dict) else {}
    next_run = str(status.get("next") or "").strip()
    cal_err = str(status.get("calendar_error") or "").strip()
    linger_raw = status.get("linger")
    linger = linger_raw if isinstance(linger_raw, dict) else {}
    parts: list[str] = []
    if status.get("enabled") and status.get("active"):
        if cal:
            parts.append(f"Timer enabled ({cal})")
        else:
            parts.append("Timer enabled and active")
    elif timer_is_present(status):
        parts.append("Timer unit exists but is not fully enabled yet")
    else:
        parts.append("No timer installed yet — enable scheduled scan to install")
    if cfg.get("profile"):
        parts.append(f"profile {cfg['profile']}")
    if next_run:
        parts.append(f"next {next_run}")
    if cal_err:
        parts.append(f"calendar error: {cal_err}")
    if linger and linger.get("linger") is False:
        parts.append("linger off (timers stop after logout)")
    return " · ".join(parts)


def timer_is_present(status: dict[str, Any]) -> bool:
    """True when a timer unit exists (status or install result)."""
    if status.get("installed"):
        return True
    if status.get("enabled") or status.get("active"):
        return True
    return bool(status.get("ok") and status.get("timer"))


def schedule_action_label(status: dict[str, Any]) -> str:
    return "Reinstall timer…" if timer_is_present(status) else "Install timer…"
