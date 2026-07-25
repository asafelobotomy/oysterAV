"""Host & audit Settings section — audit trail only (Shield owns firewall/fail2ban)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.rpc_actions import request_audit_list
from oysterav.gui.widgets.common import make_button, run_in_thread

if TYPE_CHECKING:
    from oysterav.gui.widgets.settings import SettingsPage


def build_host_audit_section(page: SettingsPage) -> None:
    prefs = Adw.PreferencesPage()
    audit = Adw.PreferencesGroup(
        title="Audit trail",
        description=(
            "Recent privileged and sensitive operations. Firewall and fail2ban live under Shield."
        ),
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
    """No-op: firewall/fail2ban moved to the Shield tab."""
    del page
