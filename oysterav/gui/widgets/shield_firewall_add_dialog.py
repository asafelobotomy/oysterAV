"""Multi-rule UFW add dialog (one confirm / one auth via ufw_batch)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.packs.firewall_batch import ssh_port_in_rules
from oysterav.gui.rpc_actions_shield import request_firewall_ufw_batch
from oysterav.gui.widgets.common import make_button
from oysterav.gui.widgets.shield_firewall_dialogs import confirm_and_run

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage

PROTO_OPTIONS = ["tcp", "udp"]
UFW_ACTIONS = ["allow", "deny", "limit", "delete"]
MAX_DIALOG_RULES = 16


class _RuleRow:
    def __init__(self) -> None:
        self.box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.port = Gtk.Entry(placeholder_text="Port")
        self.port.set_hexpand(True)
        self.proto = Gtk.DropDown.new_from_strings(PROTO_OPTIONS)
        self.action = Gtk.DropDown.new_from_strings(UFW_ACTIONS)
        self.from_addr = Gtk.Entry(placeholder_text="Source (optional)")
        self.from_addr.set_hexpand(True)
        self.remove_btn = make_button("-", row_suffix=True)
        for w in (self.port, self.proto, self.action, self.from_addr, self.remove_btn):
            self.box.append(w)

    def as_rule(self) -> dict[str, Any] | None:
        port = self.port.get_text().strip()
        if not port:
            return None
        act_item = self.action.get_selected_item()
        action = act_item.get_string() if act_item is not None else "allow"
        rule: dict[str, Any] = {
            "action": action,
            "port": port,
            "proto": PROTO_OPTIONS[self.proto.get_selected()],
        }
        src = self.from_addr.get_text().strip()
        if src:
            rule["from_addr"] = src
        if action == "delete":
            rule["rule_action"] = "allow"
        return rule


def present_ufw_multi_add_dialog(page: ShieldPage) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Add firewall rules",
        body=(
            "Numeric ports only (1–65535). Use + for more rows. "
            "All rules apply with one authentication."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.set_default_response("apply")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    outer.set_margin_top(12)
    scrolled = Gtk.ScrolledWindow()
    scrolled.set_min_content_height(120)
    scrolled.set_max_content_height(240)
    scrolled.set_propagate_natural_height(True)
    list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    scrolled.set_child(list_box)
    outer.append(scrolled)
    add_btn = make_button("+ Add another rule")
    outer.append(add_btn)
    dialog.set_extra_child(outer)

    rows: list[_RuleRow] = []

    def _sync_remove_sensitive() -> None:
        for row in rows:
            row.remove_btn.set_sensitive(len(rows) > 1)

    def _remove_row(row: _RuleRow) -> None:
        if len(rows) <= 1:
            return
        list_box.remove(row.box)
        rows.remove(row)
        _sync_remove_sensitive()

    def _add_row() -> None:
        if len(rows) >= MAX_DIALOG_RULES:
            page._set_status(f"At most {MAX_DIALOG_RULES} rules in one dialog")
            return
        row = _RuleRow()
        row.remove_btn.connect("clicked", lambda *_a, r=row: _remove_row(r))
        list_box.append(row.box)
        rows.append(row)
        _sync_remove_sensitive()

    add_btn.connect("clicked", lambda *_: _add_row())
    _add_row()

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "apply":
            return
        rules: list[dict[str, Any]] = []
        for row in rows:
            rule = row.as_rule()
            if rule is None:
                continue
            if not str(rule["port"]).isdigit():
                page._set_status(
                    "UFW rules need a numeric port (1–65535). "
                    "For app profiles use: sudo ufw allow NAME",
                )
                return
            rules.append(rule)
        if not rules:
            page._set_status("Enter at least one port")
            return
        force = ssh_port_in_rules(rules)
        labels = ", ".join(
            f"{r['action']} {r['port']}/{r['proto']}" for r in rules[:6]
        )
        extra = f" (+{len(rules) - 6} more)" if len(rules) > 6 else ""
        confirm_and_run(
            page,
            heading=f"Apply {len(rules)} UFW rule(s)?",
            body=(
                "Includes delete/deny on port 22 — can lock out SSH."
                if force
                else f"One authentication applies: {labels}{extra}."
            ),
            action_id="force" if force else "apply",
            action_label="Apply (force lockout risk)" if force else "Apply",
            destructive=force,
            worker=lambda: request_firewall_ufw_batch(
                page.client,
                rules,
                force_lockout_risk=force,
            ),
            cli_hint="oyst-cli firewall ufw batch --rule='{…}' … --confirm",
        )

    dialog.connect("response", on_response)
    dialog.present()
