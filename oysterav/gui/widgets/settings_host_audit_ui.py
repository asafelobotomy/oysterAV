"""Host & audit Settings section builders and handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.rpc_actions import (
    request_audit_list,
    request_fail2ban_unban,
    request_firewall_status,
)
from oysterav.gui.widgets.common import make_button, run_in_thread, show_command_dialog

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def build_host_audit_section(page: SettingsPage) -> None:
    prefs = Adw.PreferencesPage()

    host = Adw.PreferencesGroup(
        title="Host security",
        description="Limited firewall / fail2ban controls (full DSL remains CLI).",
    )
    page.firewall_row = Adw.ActionRow(title="Firewall")
    page.firewall_row.set_subtitle("Checking…")
    host.add(page.firewall_row)

    unban_row = Adw.EntryRow(title="fail2ban unban IP")
    unban_row.set_show_apply_button(True)
    unban_row.connect("apply", lambda *a: on_fail2ban_unban(page, *a))
    host.add(unban_row)
    prefs.add(host)

    audit = Adw.PreferencesGroup(
        title="Audit trail",
        description="Recent privileged and sensitive operations.",
    )
    page.audit_status_row = Adw.ActionRow(title="Recent entries")
    page.audit_status_row.set_subtitle("Loading…")
    refresh_btn = make_button("Refresh", row_suffix=True)
    refresh_btn.connect("clicked", lambda *_: refresh_audit(page))
    page.audit_status_row.add_suffix(refresh_btn)
    audit.add(page.audit_status_row)
    page._audit_detail_rows = []
    page._audit_group = audit
    prefs.add(audit)

    page._add_section_page("host_audit", prefs)


def refresh_audit(page: SettingsPage) -> None:
    def worker() -> list[dict[str, Any]]:
        return request_audit_list(page.client, limit=8)

    def done(entries: list[dict[str, Any]]) -> bool:
        for row in page._audit_detail_rows:
            page._audit_group.remove(row)
        page._audit_detail_rows.clear()
        if not entries:
            page.audit_status_row.set_subtitle("No audit entries yet")
            return False
        page.audit_status_row.set_subtitle(f"Showing {len(entries)} recent entries")
        for entry in entries[:5]:
            row = Adw.ActionRow(
                title=str(entry.get("action") or entry.get("kind") or "event"),
                subtitle=str(entry.get("message") or entry.get("target") or "")[:120],
            )
            page._audit_group.add(row)
            page._audit_detail_rows.append(row)
        return False

    def failed(message: str) -> bool:
        for row in page._audit_detail_rows:
            page._audit_group.remove(row)
        page._audit_detail_rows.clear()
        page.audit_status_row.set_subtitle(f"Could not load audit trail — {message}")
        return False

    run_in_thread(worker, done, failed)


def refresh_host_security(page: SettingsPage) -> None:
    def worker() -> dict[str, Any]:
        return request_firewall_status(page.client)

    def done(status: dict[str, Any]) -> bool:
        active = status.get("active") or status.get("backend") or "unknown"
        page.firewall_row.set_subtitle(f"Backend: {active}")
        return False

    def failed(message: str) -> bool:
        page.firewall_row.set_subtitle(f"Status unavailable — {message}")
        return False

    run_in_thread(worker, done, failed)


def on_fail2ban_unban(page: SettingsPage, row: Adw.EntryRow, *_args: object) -> None:
    ip = row.get_text().strip()
    if not ip:
        return

    def worker() -> dict[str, Any]:
        return request_fail2ban_unban(page.client, ip)

    def done(result: dict[str, Any]) -> bool:
        if result.get("ok"):
            page._set_status(f"Unbanned {ip}")
            row.set_text("")
        else:
            show_command_dialog(
                page._window,
                heading="fail2ban unban failed",
                body=str(result.get("message") or "failed"),
                copy_text=f"oyst-cli fail2ban unban {ip}",
            )
        return False

    run_in_thread(worker, done, page._apply_error)
