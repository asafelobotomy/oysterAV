"""Shield firewall rules UI helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.rpc_actions_shield import (
    request_firewall_firewalld_rich_rule,
    request_firewall_set_enabled,
)
from oysterav.gui.widgets.common import make_button
from oysterav.gui.widgets.shield_firewall_dialogs import (
    confirm_and_run,
    present_add_rule_dialog,
    present_ufw_default_dialog,
)

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage

__all__ = [
    "build_rules_section",
    "confirm_and_run",
    "on_managed_toggled",
    "present_add_rule_dialog",
    "present_backend_picker",
    "present_ufw_default_dialog",
    "update_firewall_posture",
    "wire_rich_rule_buttons",
]


def update_firewall_posture(page: ShieldPage, active: str, *, conflict: bool) -> None:
    """1A: Switch = managed UFW/firewalld only; nftables is a subtitle note."""
    managed = active in {"ufw", "firewalld"}
    page.fw_managed_row.set_sensitive(not conflict)
    if conflict:
        page.fw_managed_row.set_subtitle(f"Conflict · resolve UFW vs firewalld ({active})")
        page.fw_managed_row.set_active(False)
    elif managed:
        page.fw_managed_row.set_subtitle(f"On · {active}")
        page.fw_managed_row.set_active(True)
    elif active == "nft-direct":
        page.fw_managed_row.set_subtitle(
            "Host nftables filtering · managed firewall off",
        )
        page.fw_managed_row.set_active(False)
    else:
        page.fw_managed_row.set_subtitle("Off · no managed firewall")
        page.fw_managed_row.set_active(False)
    page._rich_group.set_visible(active == "firewalld" and not conflict)
    btns = getattr(page, "_fw_action_btns", {})
    for key, btn in btns.items():
        if key == "refresh":
            btn.set_visible(True)
            continue
        if key == "choose":
            btn.set_visible(conflict or active in {"none", "nft-direct"})
            continue
        if key == "add":
            btn.set_visible(managed and not conflict)
        elif key == "ufw_defaults":
            btn.set_visible(active == "ufw" and not conflict)
        elif key == "fw_reload":
            btn.set_visible(active == "firewalld" and not conflict)


def build_rules_section(
    *,
    on_export: Callable[[], None],
    on_add: Callable[[], None],
    on_default: Callable[[], None],
    on_fw_reload: Callable[[], None],
    on_choose: Callable[[], None] | None = None,
) -> tuple[
    Gtk.Box,
    Gtk.TextView,
    Gtk.TextBuffer,
    Adw.PreferencesGroup,
    Adw.EntryRow,
    Gtk.Button,
    Gtk.Button,
    dict[str, Gtk.Button],
]:
    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    group = Adw.PreferencesGroup(
        title="Firewall rules",
        description=(
            "Structured allow/deny when UFW or firewalld is managed. "
            "firewalld rich rules below; plan/nft stay CLI."
        ),
    )
    actions = Adw.ActionRow(title="Actions")
    btns: dict[str, Gtk.Button] = {}
    for key, label, cb in (
        ("refresh", "Refresh", on_export),
        ("add", "Add rule…", on_add),
        ("ufw_defaults", "UFW defaults…", on_default),
        ("fw_reload", "firewalld reload", on_fw_reload),
        ("choose", "Choose managed firewall…", on_choose or (lambda: None)),
    ):
        btn = make_button(label, row_suffix=True)
        btn.connect("clicked", lambda *_a, c=cb: c())
        actions.add_suffix(btn)
        btns[key] = btn
    group.add(actions)
    outer.append(group)

    rich = Adw.PreferencesGroup(title="firewalld rich rules")
    rich.set_visible(False)
    entry = Adw.EntryRow(title="Rich rule")
    entry.set_show_apply_button(False)
    rich.add(entry)
    btn_row = Adw.ActionRow(title="Apply")
    add_btn = make_button("Add", row_suffix=True)
    rem_btn = make_button("Remove", row_suffix=True)
    btn_row.add_suffix(add_btn)
    btn_row.add_suffix(rem_btn)
    rich.add(btn_row)
    outer.append(rich)

    scrolled = Gtk.ScrolledWindow()
    scrolled.set_min_content_height(160)
    scrolled.set_vexpand(True)
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
    view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    buf = view.get_buffer()
    scrolled.set_child(view)
    outer.append(scrolled)
    return outer, view, buf, rich, entry, add_btn, rem_btn, btns


def present_backend_picker(page: ShieldPage) -> None:
    """Dialog to soft-swap managed backend (same as wizard select)."""
    from oysterav.gui.rpc_actions_shield import request_firewall_select

    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Choose managed firewall",
        body="Stops the other manager if needed, then enables the choice (SSH-safe).",
    )
    dialog.add_response("cancel", "Cancel")
    for key in ("ufw", "firewalld", "none"):
        dialog.add_response(key, "Keep off" if key == "none" else key)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response not in {"ufw", "firewalld", "none"}:
            return
        confirm_and_run(
            page,
            heading=f"Select {response}?",
            body="Authentication is required to change the managed firewall.",
            action_id="select",
            action_label="Apply",
            destructive=response == "none",
            worker=lambda: request_firewall_select(page.client, response),
            cli_hint=f"oyst-cli firewall select {response} --confirm",
            after_ok=lambda _r: page.refresh(),
        )

    dialog.connect("response", on_response)
    dialog.present()


def wire_rich_rule_buttons(
    page: ShieldPage,
    entry: Adw.EntryRow,
    add_btn: Gtk.Button,
    rem_btn: Gtk.Button,
) -> None:

    def _run(action: str) -> None:
        rule = entry.get_text().strip()
        if not rule:
            page._set_status("Enter a rich rule first")
            return
        confirm_and_run(
            page,
            heading=f"{action.title()} rich rule?",
            body=rule,
            action_id=action,
            action_label=action.title(),
            destructive=action == "remove",
            worker=lambda: request_firewall_firewalld_rich_rule(page.client, action, rule),
            cli_hint=(f"oyst-cli firewall firewalld rich-rule {action} '{rule}' --confirm"),
        )

    add_btn.connect("clicked", lambda *_: _run("add"))
    rem_btn.connect("clicked", lambda *_: _run("remove"))


def on_managed_toggled(page: ShieldPage, row: Adw.SwitchRow) -> None:
    if page._loading:
        return
    want = row.get_active()
    if want:
        confirm_and_run(
            page,
            heading="Enable managed firewall?",
            body=(
                "Enables UFW or firewalld when installed (SSH-safe). "
                "Host nftables tables are not edited; a managed layer may start "
                "alongside existing host filtering."
            ),
            action_id="enable",
            action_label="Enable",
            worker=lambda: request_firewall_set_enabled(page.client, True),
            cli_hint="oyst-cli firewall ensure-enable --confirm",
            on_cancel=lambda: _revert_switch(page, False),
            on_fail=lambda: _revert_switch(page, False),
            after_ok=lambda _r: _after_managed_enable(page),
        )
        return
    confirm_and_run(
        page,
        heading="Disable managed firewall?",
        body="Stops UFW or firewalld. Host nftables rules are left unchanged.",
        action_id="disable",
        action_label="Disable",
        destructive=True,
        worker=lambda: request_firewall_set_enabled(page.client, False),
        cli_hint="oyst-cli firewall ufw disable --confirm",
        on_cancel=lambda: _revert_switch(page, True),
        on_fail=lambda: _revert_switch(page, True),
        after_ok=lambda _r: page.refresh(),
    )


def _after_managed_enable(page: ShieldPage) -> None:
    page.refresh()


def _revert_switch(page: ShieldPage, active: bool) -> None:
    page._loading = True
    page.fw_managed_row.set_active(active)
    page._loading = False
