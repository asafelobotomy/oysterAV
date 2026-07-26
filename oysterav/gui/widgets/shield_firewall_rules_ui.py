"""Shield firewall rules list — structured rows with selection + Remove."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.rpc_actions_shield import (
    request_firewall_ufw_batch,
    request_firewall_ufw_rule,
)
from oysterav.gui.widgets.common import make_button
from oysterav.gui.widgets.shield_firewall_dialogs import confirm_and_run

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage


def build_rules_list() -> tuple[Adw.PreferencesGroup, Gtk.ScrolledWindow, Gtk.TextBuffer]:
    """Row list for UFW; monospace fallback for firewalld / unparsed dumps."""
    group = Adw.PreferencesGroup(title="Current rules")
    scrolled = Gtk.ScrolledWindow()
    scrolled.set_min_content_height(120)
    scrolled.set_max_content_height(220)
    scrolled.set_vexpand(False)
    scrolled.set_visible(False)
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
    view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    buf = view.get_buffer()
    scrolled.set_child(view)
    return group, scrolled, buf


def update_delete_selected_sensitive(page: ShieldPage) -> None:
    btn = getattr(page, "_fw_action_btns", {}).get("delete_selected")
    if btn is None:
        return
    selected = any(
        check.get_active() for check, entry in page._rule_checks if entry.get("removable")
    )
    btn.set_sensitive(bool(selected) and page._fw_active == "ufw")


def rebuild_rule_rows(
    page: ShieldPage,
    entries: list[dict[str, Any]],
    *,
    fallback_text: str,
    backend: str,
) -> None:
    """Replace rule ActionRows; show text dump when not UFW-structured."""
    for row in page._rule_rows:
        page._rules_list_group.remove(row)
    page._rule_rows.clear()
    page._rule_checks.clear()
    page._rules_empty_row = None

    text = fallback_text.strip()
    if backend == "ufw" and entries:
        page._rules_fallback.set_visible(False)
        for entry in entries:
            title = str(entry.get("title") or "rule")
            subtitle = str(entry.get("subtitle") or "")
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            if entry.get("removable"):
                check = Gtk.CheckButton()
                check.set_valign(Gtk.Align.CENTER)
                check.connect(
                    "toggled",
                    lambda *_a: update_delete_selected_sensitive(page),
                )
                row.add_prefix(check)
                page._rule_checks.append((check, entry))
                btn = make_button("Remove", row_suffix=True, destructive=True)
                btn.connect(
                    "clicked",
                    lambda *_a, e=entry: present_remove_rule(page, e),
                )
                row.add_suffix(btn)
            page._rules_list_group.add(row)
            page._rule_rows.append(row)
        update_delete_selected_sensitive(page)
        return

    if backend == "ufw":
        page._rules_fallback.set_visible(False)
        empty = Adw.ActionRow(
            title="No rules yet",
            subtitle="Use Add rule… to allow or deny a port",
        )
        page._rules_list_group.add(empty)
        page._rules_empty_row = empty
        page._rule_rows.append(empty)
        update_delete_selected_sensitive(page)
        return

    page.rules_buffer.set_text(text or "(no rules)")
    page._rules_fallback.set_visible(True)
    note = Adw.ActionRow(
        title="Zone dump",
        subtitle="Use Add rule… for ports/services; rich rules above",
    )
    page._rules_list_group.add(note)
    page._rules_empty_row = note
    page._rule_rows.append(note)
    update_delete_selected_sensitive(page)


def _entry_to_delete_rule(entry: dict[str, Any]) -> dict[str, Any] | None:
    port = str(entry.get("port") or "")
    if not port.isdigit():
        return None
    rule_action = str(entry.get("action") or "allow").lower()
    if rule_action not in {"allow", "deny", "limit", "reject"}:
        rule_action = "allow"
    rule: dict[str, Any] = {
        "action": "delete",
        "port": port,
        "proto": str(entry.get("proto") or "tcp"),
        "rule_action": rule_action,
    }
    from_addr = entry.get("from_addr")
    if isinstance(from_addr, str) and from_addr.strip():
        rule["from_addr"] = from_addr.strip()
    return rule


def present_remove_rule(page: ShieldPage, entry: dict[str, Any]) -> None:
    rule = _entry_to_delete_rule(entry)
    if rule is None:
        page._set_status("This rule cannot be removed from the list")
        return
    port = str(rule["port"])
    proto = str(rule["proto"])
    rule_action = str(rule["rule_action"])
    force = port == "22"
    label = f"{rule_action} {port}/{proto}"
    confirm_and_run(
        page,
        heading=f"Remove {port}/{proto}?",
        body=(
            "This can lock out SSH. Prefer keeping an allow rule for 22."
            if force
            else f"Delete the UFW rule ({label})."
        ),
        action_id="force" if force else "remove",
        action_label="Remove (force lockout risk)" if force else "Remove",
        destructive=True,
        worker=lambda: request_firewall_ufw_rule(
            page.client,
            "delete",
            port=port,
            proto=proto,
            from_addr=rule.get("from_addr") if isinstance(rule.get("from_addr"), str) else None,
            rule_action=rule_action,
            force_lockout_risk=force,
        ),
        cli_hint=(
            f"oyst-cli firewall ufw delete --port {port} --proto {proto}"
            f" --rule-action {rule_action}"
            + (" --force-lockout-risk" if force else "")
            + " --confirm"
        ),
    )


def present_delete_selected(page: ShieldPage) -> None:
    rules: list[dict[str, Any]] = []
    for check, entry in page._rule_checks:
        if not check.get_active() or not entry.get("removable"):
            continue
        rule = _entry_to_delete_rule(entry)
        if rule is not None:
            rules.append(rule)
    if not rules:
        page._set_status("Select one or more rules to delete")
        return
    force = any(r.get("port") == "22" for r in rules)
    confirm_and_run(
        page,
        heading=f"Delete {len(rules)} selected rule(s)?",
        body=(
            "Includes port 22 — can lock out SSH."
            if force
            else "One authentication deletes all selected UFW rules."
        ),
        action_id="force" if force else "remove",
        action_label="Delete (force lockout risk)" if force else "Delete selected",
        destructive=True,
        worker=lambda: request_firewall_ufw_batch(
            page.client,
            rules,
            force_lockout_risk=force,
        ),
        cli_hint="oyst-cli firewall ufw batch --rule='{…}' … --confirm",
    )
