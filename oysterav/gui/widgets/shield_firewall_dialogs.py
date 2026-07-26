"""Shield firewall mutation dialogs."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.rpc_actions_shield import (
    request_firewall_firewalld_port,
    request_firewall_firewalld_service,
    request_firewall_ufw_default,
)
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage

PROTO_OPTIONS = ["tcp", "udp"]
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
    if active == "ufw":
        from oysterav.gui.widgets.shield_firewall_add_dialog import present_ufw_multi_add_dialog

        present_ufw_multi_add_dialog(page)
        return
    body = "Enter a port (e.g. 443/tcp) or firewalld service name (ssh, http, …)."
    port_ph = "Port or service (ssh, http, …)"
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Add firewall rule",
        body=body,
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.set_default_response("apply")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)

    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.set_margin_top(12)
    port_entry = Gtk.Entry(placeholder_text=port_ph)
    box.append(port_entry)
    proto = Gtk.DropDown.new_from_strings(PROTO_OPTIONS)
    box.append(proto)
    action_dd = Gtk.DropDown.new_from_strings(
        ["add-port", "add-service", "remove-port", "remove-service"],
    )
    box.append(action_dd)
    dialog.set_extra_child(box)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "apply":
            return
        text = port_entry.get_text().strip()
        if not text:
            return
        act_item = action_dd.get_selected_item()
        act = act_item.get_string() if act_item is not None else ""
        if act in {"add-service", "remove-service"}:
            force = act == "remove-service" and text.lower() == "ssh"
            confirm_and_run(
                page,
                heading=f"firewalld {act} {text}?",
                body=(
                    "Removing the SSH service can lock you out."
                    if force
                    else f"Apply firewalld {act} for service {text}."
                ),
                action_id="force" if force else "apply",
                action_label="Apply (force lockout risk)" if force else "Apply",
                destructive=force or act.startswith("remove"),
                worker=lambda: request_firewall_firewalld_service(
                    page.client,
                    act,
                    text,
                    force_lockout_risk=force,
                ),
                cli_hint=(
                    f"oyst-cli firewall firewalld {act} {text}"
                    + (" --force-lockout-risk" if force else "")
                    + " --confirm"
                ),
            )
            return
        proto_s = PROTO_OPTIONS[proto.get_selected()]
        spec = text if "/" in text else f"{text}/{proto_s}"
        force = act == "remove-port" and spec.split("/", 1)[0] == "22"
        confirm_and_run(
            page,
            heading=f"firewalld {act} {spec}?",
            body=(
                "Removing port 22 can lock out SSH."
                if force
                else f"Apply firewalld {act} for {spec}."
            ),
            action_id="force" if force else "apply",
            action_label="Apply (force lockout risk)" if force else "Apply",
            destructive=force or act.startswith("remove"),
            worker=lambda: request_firewall_firewalld_port(
                page.client,
                act,
                spec,
                force_lockout_risk=force,
            ),
            cli_hint=(
                f"oyst-cli firewall firewalld {act} {spec}"
                + (" --force-lockout-risk" if force else "")
                + " --confirm"
            ),
        )

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
        direction_s = DEFAULT_DIRS[direction.get_selected()]
        policy_s = DEFAULT_POLICIES[policy.get_selected()]
        force = response == "force"
        run_in_thread(
            lambda: request_firewall_ufw_default(
                page.client,
                direction_s,
                policy_s,
                force_lockout_risk=force,
            ),
            lambda r: page._mutation_done(r, f"Default {direction_s}={policy_s}"),
            page._fail_status,
        )

    dialog.connect("response", on_response)
    dialog.present()
