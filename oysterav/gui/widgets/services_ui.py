"""Settings Services / Auth UI helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.services import SERVICE_NAMES
from oysterav.gui.rpc_actions import (
    request_auth_grant,
    request_auth_revoke,
    request_auth_status,
    request_helper_install,
    request_services_set,
    request_services_status,
)
from oysterav.gui.widgets.common import make_button, run_in_thread

_SERVICE_TITLES = {
    "clamd": "ClamAV daemon (clamd)",
    "clamonacc": "On-access (clamonacc) — status",
    "freshclam-timer": "Signature update timer",
    "fail2ban": "fail2ban",
    "maldet-monitor": "maldet monitor",
    "schedule-linger": "User linger (scheduled scans)",
}


def build_services_group(
    client: OystClient,
    *,
    window: Gtk.Window | None,
    on_status: Callable[[str], None] | None,
) -> tuple[Adw.PreferencesGroup, Callable[[], None]]:
    """Build Services preferences group; returns (group, refresh_fn)."""
    _ = window
    group = Adw.PreferencesGroup(
        title="Services",
        description="Start/stop oysterAV-related system services (polkit may prompt).",
    )
    helper_row = Adw.ActionRow(
        title="Privileged helper",
        subtitle="Checking…",
    )
    install_btn = make_button("Install")
    install_btn.set_valign(Gtk.Align.CENTER)
    install_btn.add_css_class("suggested-action")
    helper_row.add_suffix(install_btn)
    group.add(helper_row)

    auth_switch = Adw.SwitchRow(
        title="Passwordless service control",
        subtitle="Checking…",
    )
    group.add(auth_switch)

    switches: dict[str, Adw.SwitchRow] = {}
    status_rows: dict[str, Adw.ActionRow] = {}
    for name in SERVICE_NAMES:
        title = _SERVICE_TITLES.get(name, name)
        if name == "clamonacc":
            # Enable/disable lives under Real-time (single control plane).
            row = Adw.ActionRow(title=title)
            row.set_subtitle("—")
            status_rows[name] = row
            group.add(row)
            continue
        row = Adw.SwitchRow(title=title)
        row.set_subtitle("—")
        switches[name] = row
        group.add(row)

    state: dict[str, Any] = {"loading": True, "helper_ok": False}

    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    def _service_subtitle(name: str, info: dict[str, Any], *, helper_ok: bool) -> str:
        if name == "schedule-linger":
            running = bool(info.get("running"))
            state = "enabled" if running else "disabled"
            return f"{state} — allows user timers after logout (Scheduling may also prompt)"
        if not helper_ok:
            return "Requires privileged helper — use Install above"
        running = bool(info.get("running"))
        enabled = bool(info.get("enabled"))
        base = f"{'running' if running else 'stopped'}"
        if enabled:
            base += "; enabled at boot"
        details = info.get("details") or {}
        if name == "clamonacc":
            unit_hint = "toggle under Real-time (paths/excludes there too)"
            if not running:
                nested = details.get("details") if isinstance(details, dict) else None
                if isinstance(nested, dict) and not nested.get("clamd_running"):
                    return f"{base} — needs clamd running; {unit_hint}"
                paths: list[Any] = []
                if isinstance(nested, dict):
                    paths = list(nested.get("configured_paths") or [])
                elif isinstance(details, dict):
                    paths = list(details.get("configured_paths") or [])
                if not paths:
                    return f"{base} — add watched paths under Real-time"
            return f"{base} — {unit_hint}"
        if name == "maldet-monitor" and not running:
            overlaps = details.get("clamonacc_overlaps") if isinstance(details, dict) else None
            if overlaps:
                return f"{base} — paths overlap clamonacc"
            if isinstance(details, dict) and details.get("inotify_tools") is False:
                return f"{base} — install inotify-tools"
        return base

    def refresh() -> None:
        state["loading"] = True

        def worker() -> dict[str, Any]:
            return {
                "services": request_services_status(client),
                "auth": request_auth_status(client),
            }

        def done(payload: dict[str, Any]) -> bool:
            services = (payload.get("services") or {}).get("services") or {}
            auth = payload.get("auth") or {}
            helper = auth.get("helper") or {}
            grant = auth.get("service_lifecycle") or {}
            helper_ok = bool(helper.get("installed") and helper.get("policy_current", True))
            state["helper_ok"] = helper_ok
            if helper_ok:
                helper_row.set_subtitle(f"Installed (policy v{helper.get('policy_version', '?')})")
                install_btn.set_label("Reinstall")
                install_btn.remove_css_class("suggested-action")
            elif helper.get("installed"):
                helper_row.set_subtitle("Installed but policy outdated — reinstall helper")
                install_btn.set_label("Update")
                install_btn.add_css_class("suggested-action")
            else:
                helper_row.set_subtitle("Not installed — privileged actions will fail")
                install_btn.set_label("Install")
                install_btn.add_css_class("suggested-action")
            install_btn.set_sensitive(True)
            if grant.get("granted"):
                auth_switch.set_subtitle(
                    f"Granted for {grant.get('granted_user')} "
                    "(systemctl/maldet-config only; polkit may still prompt)"
                )
            else:
                auth_switch.set_subtitle(
                    "Off — polkit will prompt for admin passwords on service changes"
                )
            state["loading"] = True
            auth_switch.set_active(bool(grant.get("granted")))
            auth_switch.set_sensitive(True)
            for name, row in switches.items():
                info = services.get(name) or {}
                running = bool(info.get("running"))
                row.set_active(running)
                row.set_subtitle(_service_subtitle(name, info, helper_ok=helper_ok))
                row.set_sensitive(helper_ok or name == "schedule-linger")
            for name, row in status_rows.items():
                info = services.get(name) or {}
                row.set_subtitle(_service_subtitle(name, info, helper_ok=helper_ok))
            state["loading"] = False
            return False

        def failed(message: str) -> bool:
            helper_row.set_subtitle(f"Status failed: {message}")
            state["helper_ok"] = False
            install_btn.set_sensitive(True)
            auth_switch.set_sensitive(False)
            for row in switches.values():
                row.set_sensitive(False)
            state["loading"] = False
            return False

        run_in_thread(worker, done, failed)

    def _on_install(*_a: object) -> None:
        install_btn.set_sensitive(False)
        _status("Installing privileged helper (polkit may prompt)…")

        def worker() -> dict[str, Any]:
            return request_helper_install(client)

        def done(result: dict[str, Any]) -> bool:
            install_btn.set_sensitive(True)
            if result.get("ok"):
                _status("Privileged helper installed")
            else:
                _status(str(result.get("message") or "Helper install failed"))
            refresh()
            return False

        def failed(message: str) -> bool:
            install_btn.set_sensitive(True)
            _status(f"Helper install failed: {message}")
            return False

        run_in_thread(worker, done, failed)

    def _on_auth_notify(*_a: object) -> None:
        if state.get("loading"):
            return
        want_on = bool(auth_switch.get_active())
        auth_switch.set_sensitive(False)

        def worker() -> dict[str, Any]:
            if want_on:
                return request_auth_grant(client)
            return request_auth_revoke(client)

        def done(result: dict[str, Any]) -> bool:
            auth_switch.set_sensitive(True)
            if result.get("ok"):
                _status("Passwordless service control " + ("granted" if want_on else "revoked"))
            else:
                _status(str(result.get("message") or "Auth change failed"))
                state["loading"] = True
                auth_switch.set_active(not want_on)
                state["loading"] = False
            refresh()
            return False

        def failed(message: str) -> bool:
            auth_switch.set_sensitive(True)
            state["loading"] = True
            auth_switch.set_active(not want_on)
            state["loading"] = False
            _status(f"Auth change failed: {message}")
            return False

        run_in_thread(worker, done, failed)

    install_btn.connect("clicked", _on_install)
    auth_switch.connect("notify::active", _on_auth_notify)

    def _bind_switch(name: str, row: Adw.SwitchRow) -> None:
        def on_notify(*_a: object) -> None:
            if state.get("loading"):
                return
            if not state.get("helper_ok") and name != "schedule-linger":
                state["loading"] = True
                row.set_active(False)
                state["loading"] = False
                _status("Install the privileged helper before toggling services")
                return
            want_on = bool(row.get_active())
            row.set_sensitive(False)

            def worker() -> dict[str, Any]:
                return request_services_set(client, name, on=want_on)

            def done(result: dict[str, Any]) -> bool:
                row.set_sensitive(bool(state.get("helper_ok")) or name == "schedule-linger")
                if result.get("ok"):
                    _status(f"{name}: {'on' if want_on else 'off'}")
                else:
                    _status(str(result.get("message") or f"{name} failed"))
                    state["loading"] = True
                    row.set_active(not want_on)
                    state["loading"] = False
                refresh()
                return False

            def failed(message: str) -> bool:
                row.set_sensitive(bool(state.get("helper_ok")) or name == "schedule-linger")
                state["loading"] = True
                row.set_active(not want_on)
                state["loading"] = False
                _status(f"{name} failed: {message}")
                return False

            run_in_thread(worker, done, failed)

        row.connect("notify::active", on_notify)

    for svc_name, row in switches.items():
        _bind_switch(svc_name, row)

    return group, refresh
