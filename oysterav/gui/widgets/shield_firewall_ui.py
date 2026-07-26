"""Shield firewall rules UI helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

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
from oysterav.gui.widgets.shield_firewall_rules_ui import (
    build_rules_list,
    present_delete_selected,
    rebuild_rule_rows,
)

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage

__all__ = [
    "build_rules_section",
    "confirm_and_run",
    "on_managed_toggled",
    "present_add_rule_dialog",
    "present_backend_picker",
    "present_delete_selected",
    "present_ufw_default_dialog",
    "rebuild_rule_rows",
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
        elif key == "delete_selected":
            btn.set_visible(active == "ufw" and not conflict)
        elif key == "ufw_defaults":
            btn.set_visible(active == "ufw" and not conflict)
        elif key == "fw_reload":
            btn.set_visible(active == "firewalld" and not conflict)
    from oysterav.gui.widgets.shield_firewall_rules_ui import update_delete_selected_sensitive

    update_delete_selected_sensitive(page)


def build_rules_section(
    *,
    on_export: Callable[[], None],
    on_add: Callable[[], None],
    on_delete_selected: Callable[[], None],
    on_default: Callable[[], None],
    on_fw_reload: Callable[[], None],
    on_choose: Callable[[], None] | None = None,
) -> tuple[
    Gtk.Box,
    Adw.PreferencesGroup,
    Gtk.ScrolledWindow,
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
            "Allow/deny ports when UFW or firewalld is managed. "
            "Select rules to delete several at once; firewalld uses Add rule… or rich rules."
        ),
    )
    actions = Adw.ActionRow(title="Actions")
    btns: dict[str, Gtk.Button] = {}
    for key, label, cb, destructive in (
        ("refresh", "Refresh", on_export, False),
        ("add", "Add rule…", on_add, False),
        ("delete_selected", "Delete selected", on_delete_selected, True),
        ("ufw_defaults", "UFW defaults…", on_default, False),
        ("fw_reload", "firewalld reload", on_fw_reload, False),
        ("choose", "Choose managed firewall…", on_choose or (lambda: None), False),
    ):
        btn = make_button(label, row_suffix=True, destructive=destructive)
        btn.connect("clicked", lambda *_a, c=cb: c())
        if key == "delete_selected":
            btn.set_sensitive(False)
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

    rules_list, fallback, buf = build_rules_list()
    outer.append(rules_list)
    outer.append(fallback)
    return outer, rules_list, fallback, buf, rich, entry, add_btn, rem_btn, btns


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
    from oyst_core.privileged.validators import rich_rule_ssh_lockout_risk

    def _run(action: str) -> None:
        rule = entry.get_text().strip()
        if not rule:
            page._set_status("Enter a rich rule first")
            return
        force = False
        if action == "add":
            try:
                force = rich_rule_ssh_lockout_risk(rule)
            except ValueError:
                force = False
        confirm_and_run(
            page,
            heading=f"{action.title()} rich rule?",
            body=(
                f"{rule}\n\nThis rule drops/rejects SSH; force lockout risk required."
                if force
                else rule
            ),
            action_id="force" if force else action,
            action_label="Apply (force lockout risk)" if force else action.title(),
            destructive=action == "remove" or force,
            worker=lambda: request_firewall_firewalld_rich_rule(
                page.client,
                action,
                rule,
                force_lockout_risk=force,
            ),
            cli_hint=(
                f"oyst-cli firewall firewalld rich-rule {action} '{rule}'"
                + (" --force-lockout-risk" if force else "")
                + " --confirm"
            ),
        )

    add_btn.connect("clicked", lambda *_: _run("add"))
    rem_btn.connect("clicked", lambda *_: _run("remove"))


def on_managed_toggled(page: ShieldPage, row: Adw.SwitchRow) -> None:
    if page._loading:
        return
    want = row.get_active()
    if want:
        active = getattr(page, "_fw_active", "") or ""
        nft_note = ""
        if active == "nft-direct":
            nft_note = (
                " Host nftables may already filter traffic; enabling adds a managed "
                "layer oysterAV can edit."
            )

        def _cancel_enable() -> None:
            _clear_expect(page)
            _revert_switch(page, False)

        def _start_enable() -> dict[str, Any]:
            page._expect_managed = True
            return request_firewall_set_enabled(page.client, True)

        confirm_and_run(
            page,
            heading="Enable managed firewall?",
            body=(
                "Enables UFW or firewalld when installed (SSH-safe). "
                "Host nftables tables are not edited; a managed layer may start "
                f"alongside existing host filtering.{nft_note}"
            ),
            action_id="enable",
            action_label="Enable",
            worker=_start_enable,
            cli_hint="oyst-cli firewall ensure-enable --confirm",
            on_cancel=_cancel_enable,
            on_fail=_cancel_enable,
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
        cli_hint=(
            "oyst-cli firewall firewalld disable --confirm"
            if getattr(page, "_fw_active", "") == "firewalld"
            else "oyst-cli firewall ufw disable --confirm"
        ),
        on_cancel=lambda: _revert_switch(page, True),
        on_fail=lambda: _revert_switch(page, True),
        after_ok=lambda _r: page.refresh(),
    )


def _clear_expect(page: ShieldPage) -> None:
    page._expect_managed = False


def _after_managed_enable(page: ShieldPage) -> None:
    page.refresh()


def _revert_switch(page: ShieldPage, active: bool) -> None:
    page._loading = True
    page.fw_managed_row.set_active(active)
    page._loading = False
