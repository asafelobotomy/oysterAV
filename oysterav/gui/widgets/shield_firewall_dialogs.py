"""Shield firewall mutation dialogs."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.rpc_actions_shield import request_firewall_ufw_rule
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage

PROTO_OPTIONS = ["tcp", "udp"]
UFW_ACTIONS = ["allow", "deny", "limit", "delete"]
DEFAULT_DIRS = ["incoming", "outgoing", "routed"]
DEFAULT_POLICIES = ["allow", "deny", "reject"]


def confirm_and_run(
    page: ShieldPage,
    *,
    heading: str,
    body: str,
    action_id: str,
    action_label: str,
    worker: Callable[[], dict[str, Any]],
    cli_hint: str,
    destructive: bool = False,
    on_cancel: Callable[[], None] | None = None,
    on_fail: Callable[[], None] | None = None,
    after_ok: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading=heading,
        body=body,
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response(action_id, action_label)
    if destructive:
        dialog.set_response_appearance(action_id, Adw.ResponseAppearance.DESTRUCTIVE)
    else:
        dialog.set_response_appearance(action_id, Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != action_id:
            if on_cancel:
                on_cancel()
            return

        def done(result: dict[str, Any]) -> bool:
            if not result.get("ok"):
                if on_fail:
                    on_fail()
                return page._mutation_done(result, str(result.get("message") or action_label))
            if after_ok is not None:
                after_ok(result)
                page._set_status(str(result.get("message") or action_label))
                return False
            return page._mutation_done(result, str(result.get("message") or action_label))

        def failed(message: str) -> bool:
            if on_fail:
                on_fail()
            show_command_dialog(
                page._window,
                heading=heading.replace("?", " failed"),
                body=message,
                copy_text=cli_hint,
            )
            return False

        run_in_thread(worker, done, failed)

    dialog.connect("response", on_response)
    dialog.present()


def present_add_rule_dialog(page: ShieldPage) -> None:
    active = page._fw_active
    if active not in {"ufw", "firewalld"}:
        page._set_status("No mutable firewall backend")
        return
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Add firewall rule",
        body="Enter a port (e.g. 22) or firewalld service name.",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.set_default_response("apply")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(12)
    port_entry = Gtk.Entry(placeholder_text="Port or service (ssh, http, …)")
    box.append(port_entry)
    proto = Gtk.DropDown.new_from_strings(PROTO_OPTIONS)
    box.append(proto)
    action_dd = Gtk.DropDown.new_from_strings(
        UFW_ACTIONS
        if active == "ufw"
        else ["add-port", "add-service", "remove-port", "remove-service"],
    )
    box.append(action_dd)
    from_entry = Gtk.Entry(placeholder_text="Optional source (UFW allow/deny)")
    if active == "ufw":
        box.append(from_entry)
    dialog.set_extra_child(box)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "apply":
            return
        text = port_entry.get_text().strip()
        if not text:
            return
        act_item = action_dd.get_selected_item()
        act = act_item.get_string() if act_item is not None else ""
        if active == "ufw":
            from_addr = from_entry.get_text().strip() or None
            proto_s = PROTO_OPTIONS[proto.get_selected()]
            if act in {"delete", "deny"} and text == "22":
                confirm_and_run(
                    page,
                    heading=f"UFW {act} port 22?",
                    body="This can lock out SSH. Prefer an allow rule for 22 first.",
                    action_id="force",
                    action_label="Apply (force lockout risk)",
                    destructive=True,
                    worker=lambda: request_firewall_ufw_rule(
                        page.client,
                        act,
                        port=text,
                        proto=proto_s,
                        from_addr=from_addr,
                        force_lockout_risk=True,
                    ),
                    cli_hint=(
                        f"oyst-cli firewall ufw {act} --port 22 --force-lockout-risk --confirm"
                    ),
                )
                return
            page.apply_ufw_rule(
                act,
                port=text,
                proto=proto_s,
                from_addr=from_addr,
            )
            return
        if act in {"add-service", "remove-service"}:
            page.apply_firewalld_service(act, text)
        else:
            proto_s = PROTO_OPTIONS[proto.get_selected()]
            spec = text if "/" in text else f"{text}/{proto_s}"
            page.apply_firewalld_port(act, spec)

    dialog.connect("response", on_response)
    dialog.present()


def present_ufw_default_dialog(page: ShieldPage) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Set UFW default policy",
        body="Incoming deny/reject requires an SSH allow rule unless forced.",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.add_response("force", "Apply (force lockout risk)")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(12)
    direction = Gtk.DropDown.new_from_strings(DEFAULT_DIRS)
    policy = Gtk.DropDown.new_from_strings(DEFAULT_POLICIES)
    box.append(direction)
    box.append(policy)
    dialog.set_extra_child(box)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response not in {"apply", "force"}:
            return
        page.apply_ufw_default(
            DEFAULT_DIRS[direction.get_selected()],
            DEFAULT_POLICIES[policy.get_selected()],
            force=response == "force",
        )

    dialog.connect("response", on_response)
    dialog.present()
