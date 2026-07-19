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
    parent_win = dialog_parent(window, parent)
    if on_complete:
        on_complete(result)
    if result.get("ok") and result.get("enabled"):
        message = str(result.get("message", "Daily scan timer enabled"))
        if on_status:
            on_status(message)
        linger = result.get("linger", {})
        advisory = result.get("linger_advisory")
        if advisory and isinstance(linger, dict) and not linger.get("linger", True):
            _prompt_enable_linger(
                parent_win,
                str(linger.get("enable_hint", "")),
                client=client,
                on_status=on_status,
                on_complete=lambda: on_complete(result) if on_complete else None,
            )
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


def _prompt_enable_linger(
    window: Gtk.Window | None,
    hint: str,
    *,
    client: OystClient | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    dialog = Adw.MessageDialog(
        transient_for=window,
        heading="Enable linger for scheduled scans?",
        body=(
            "Your user session has linger disabled, so timers stop when you log out.\n\n"
            "Enable linger now (requires admin), or copy the command for later."
        ),
    )
    dialog.add_response("later", "Not now")
    dialog.add_response("copy", "Copy command")
    if client is not None:
        dialog.add_response("enable", "Enable linger")
    dialog.set_default_response("enable" if client else "later")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "copy":
            clipboard = Gdk.Display.get_default().get_clipboard()
            clipboard.set(Gdk.ContentProvider.new_for_value(hint))
        elif response == "enable" and client is not None:
            enable_linger_from_gui(
                client,
                window=window,
                on_status=on_status,
                on_complete=on_complete,
            )

    dialog.connect("response", on_response)
    dialog.present()


def enable_linger_from_gui(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    on_status: Callable[[str], None] | None = None,
    on_complete: Callable[[], None] | None = None,
) -> None:
    parent_win = dialog_parent(window, parent)

    def done(result: dict[str, Any]) -> bool:
        if result.get("ok") or result.get("linger"):
            if on_status:
                on_status("Linger enabled for scheduled scans")
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
        if on_complete:
            on_complete()
        return False

    run_in_thread(
        client.linger_enable,
        done,
        lambda m: on_status(f"Linger failed: {m}") if on_status else False,
    )


def apply_schedule_timer(
    client: OystClient,
    *,
    window: Gtk.Window | None = None,
    parent: Gtk.Window | None = None,
    smoke_test: bool = False,
    on_status: Callable[[str], None] | None = None,
    on_error: Callable[[str], None] | None = None,
    on_complete: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Materialize systemd units from current schedule config."""
    parent_win = dialog_parent(window, parent)

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

    run_in_thread(lambda: client.schedule_apply(smoke_test=smoke_test), done, fail)


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
