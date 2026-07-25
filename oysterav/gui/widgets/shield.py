"""Shield tab — host firewall + fail2ban posture."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.rpc_actions import request_fail2ban_unban, request_firewall_status
from oysterav.gui.rpc_actions_shield import (
    request_fail2ban_banned,
    request_fail2ban_jail_disable,
    request_fail2ban_jail_enable,
    request_fail2ban_reload,
    request_fail2ban_status,
    request_firewall_export,
    request_firewall_firewalld_port,
    request_firewall_firewalld_reload,
    request_firewall_firewalld_service,
    request_firewall_rules,
    request_firewall_ufw_default,
    request_firewall_ufw_rule,
)
from oysterav.gui.widgets.common import (
    make_button,
    make_scrolled_page,
    run_in_thread,
    show_command_dialog,
)
from oysterav.gui.widgets import shield_fail2ban_ui, shield_firewall_ui


class ShieldPage:
    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self._window = window
        self._on_status = on_status
        self._loading = False
        self._fw_active = "none"
        self._expect_managed = False
        self._jail_rows: list[Adw.ActionRow] = []
        self._ban_rows: list[Adw.ActionRow] = []
        self._fw_action_btns: dict[str, Gtk.Button] = {}
        self._choose_fw_btn: Gtk.Button | None = None

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)
        root.set_margin_start(12)
        root.set_margin_end(12)

        self._posture = Adw.PreferencesGroup(title="Firewall")
        self.fw_managed_row = Adw.SwitchRow(title="Managed firewall")
        self.fw_managed_row.set_subtitle("Loading…")
        self.fw_managed_row.connect(
            "notify::active",
            lambda row, *_: shield_firewall_ui.on_managed_toggled(self, row),
        )
        self._posture.add(self.fw_managed_row)
        root.append(self._posture)

        (
            self._rules_box,
            self.rules_view,
            self.rules_buffer,
            self._rich_group,
            rich_entry,
            rich_add,
            rich_rem,
            self._fw_action_btns,
        ) = shield_firewall_ui.build_rules_section(
            on_export=self._on_export_rules,
            on_add=self._on_add_rule,
            on_default=self._on_ufw_default,
            on_fw_reload=self._on_firewalld_reload,
            on_choose=lambda: shield_firewall_ui.present_backend_picker(self),
        )
        shield_firewall_ui.wire_rich_rule_buttons(self, rich_entry, rich_add, rich_rem)
        root.append(self._rules_box)

        self._f2b_group = Adw.PreferencesGroup(title="Intrusion prevention")
        self.f2b_service_row = Adw.SwitchRow(title="fail2ban service")
        self.f2b_service_row.set_subtitle("Start or stop the fail2ban system service")
        self.f2b_service_row.connect("notify::active", self._on_f2b_service_toggled)
        self._f2b_group.add(self.f2b_service_row)
        reload_row = Adw.ActionRow(title="Reload fail2ban")
        reload_btn = make_button("Reload", row_suffix=True)
        reload_btn.connect("clicked", lambda *_: self._on_f2b_reload(False))
        clear_btn = make_button("Reload and clear bans", row_suffix=True)
        clear_btn.connect("clicked", lambda *_: self._on_f2b_reload(True))
        reload_row.add_suffix(reload_btn)
        reload_row.add_suffix(clear_btn)
        self._f2b_group.add(reload_row)
        self._jails_header = Adw.ActionRow(title="Jails")
        self._jails_header.set_subtitle("Loading…")
        self._f2b_group.add(self._jails_header)
        root.append(self._f2b_group)

        self._bans_group = Adw.PreferencesGroup(title="Banned IPs")
        unban_row = Adw.EntryRow(title="Unban IP")
        unban_row.set_show_apply_button(True)
        unban_row.connect("apply", lambda *a: self._on_unban_entry(*a))
        self._bans_group.add(unban_row)
        self._bans_status = Adw.ActionRow(title="Current bans")
        self._bans_status.set_subtitle("Not loaded — authenticate to refresh")
        load_bans = make_button("Refresh bans", row_suffix=True)
        load_bans.connect("clicked", lambda *_: self._on_load_bans())
        self._bans_status.add_suffix(load_bans)
        self._bans_group.add(self._bans_status)
        root.append(self._bans_group)

        self.widget = make_scrolled_page(root)

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _fail_status(self, message: str) -> bool:
        self._set_status(message)
        return False

    def refresh(self) -> None:
        def worker() -> dict[str, Any]:
            # Skip fail2ban.banned — polkit; use Refresh bans instead.
            return {
                "fw": request_firewall_status(self.client),
                "rules": request_firewall_rules(self.client),
                "f2b": request_fail2ban_status(self.client),
                "services": self.client.services_status(),
            }

        def done(data: dict[str, Any]) -> bool:
            self._apply_data(data)
            return False

        def failed(message: str) -> bool:
            self.fw_managed_row.set_subtitle(f"Unavailable — {message}")
            return False

        run_in_thread(worker, done, failed)

    def _apply_data(self, data: dict[str, Any]) -> None:
        self._loading = True
        try:
            fw_raw = data.get("fw")
            fw: dict[str, Any] = fw_raw if isinstance(fw_raw, dict) else {}
            active = str(fw.get("active") or "none")
            self._fw_active = active
            conflict = bool(fw.get("conflict"))
            shield_firewall_ui.update_firewall_posture(self, active, conflict=conflict)
            rules_raw = data.get("rules")
            rules: dict[str, Any] = rules_raw if isinstance(rules_raw, dict) else {}
            self.rules_buffer.set_text(str(rules.get("rules") or "(no rules)"))
            editable = active in {"ufw", "firewalld"} and not conflict
            self._rules_box.set_sensitive(editable)

            services_wrap = data.get("services")
            services_outer: dict[str, Any] = (
                services_wrap if isinstance(services_wrap, dict) else {}
            )
            svc_map_raw = services_outer.get("services")
            svc_map: dict[str, Any] = svc_map_raw if isinstance(svc_map_raw, dict) else {}
            f2b_svc_raw = svc_map.get("fail2ban")
            f2b_svc: dict[str, Any] = f2b_svc_raw if isinstance(f2b_svc_raw, dict) else {}
            f2b_running = bool(f2b_svc.get("running"))
            self.f2b_service_row.set_active(f2b_running)

            f2b_raw = data.get("f2b")
            f2b: dict[str, Any] = f2b_raw if isinstance(f2b_raw, dict) else {}
            jails_raw = f2b.get("jails")
            jails: list[Any] = jails_raw if isinstance(jails_raw, list) else []
            if f2b_running:
                self._jails_header.set_subtitle(
                    f"{len(jails)} jail(s)" if jails else "Running",
                )
            else:
                self._jails_header.set_subtitle("Not running")
            shield_fail2ban_ui.rebuild_jail_rows(
                self,
                [str(j) for j in jails],
                on_enable=self._on_jail_enable,
                on_disable=self._on_jail_disable,
            )
        finally:
            self._loading = False
            if self._expect_managed:
                self._expect_managed = False
                if self._fw_active not in {"ufw", "firewalld"}:
                    shield_firewall_ui._revert_switch(self, False)
                    self._set_status(
                        "Could not confirm managed firewall is active. "
                        "Use Choose managed firewall… or oyst-cli firewall select.",
                    )

    def _on_load_bans(self) -> None:
        def worker() -> dict[str, Any]:
            return request_fail2ban_banned(self.client)

        def done(banned: dict[str, Any]) -> bool:
            jails_raw = banned.get("jails")
            jails: dict[str, Any] = jails_raw if isinstance(jails_raw, dict) else {}
            shield_fail2ban_ui.rebuild_ban_rows(self, jails, on_unban=self._on_unban_ip)
            if banned.get("ok") is False:
                self._set_status(str(banned.get("error") or "Could not load bans"))
            return False

        run_in_thread(worker, done, self._fail_status)

    def _on_export_rules(self) -> None:
        def worker() -> dict[str, Any]:
            return request_firewall_export(self.client)

        def done(result: dict[str, Any]) -> bool:
            text = str(result.get("rules") or "")
            self.rules_buffer.set_text(text or "(empty)")
            self._set_status("Firewall rules refreshed")
            return False

        run_in_thread(worker, done, lambda m: self._fail_status(f"Export failed: {m}"))

    def _on_add_rule(self) -> None:
        shield_firewall_ui.present_add_rule_dialog(self)

    def _on_ufw_default(self) -> None:
        if self._fw_active != "ufw":
            self._set_status("Defaults apply only when UFW is active")
            return
        shield_firewall_ui.present_ufw_default_dialog(self)

    def _on_firewalld_reload(self) -> None:
        if self._fw_active != "firewalld":
            self._set_status("Reload applies only when firewalld is active")
            return
        shield_firewall_ui.confirm_and_run(
            self,
            heading="Reload firewalld?",
            body="Applies permanent zone changes to the running firewall.",
            action_id="reload",
            action_label="Reload",
            worker=lambda: request_firewall_firewalld_reload(self.client),
            cli_hint="oyst-cli firewall firewalld reload --confirm",
        )

    def _on_f2b_service_toggled(self, row: Adw.SwitchRow, *_args: object) -> None:
        if self._loading:
            return
        state = "on" if row.get_active() else "off"

        def worker() -> dict[str, Any]:
            return self.client.services_set("fail2ban", state)

        def done(result: dict[str, Any]) -> bool:
            self._set_status(str(result.get("message") or f"fail2ban {state}"))
            self.refresh()
            return False

        run_in_thread(worker, done, self._fail_status)

    def _on_f2b_reload(self, unban: bool) -> None:
        body = (
            "Reload configuration and clear all bans."
            if unban
            else "Reload fail2ban configuration."
        )
        shield_firewall_ui.confirm_and_run(
            self,
            heading="Reload fail2ban?",
            body=body,
            action_id="reload",
            action_label="Reload",
            destructive=unban,
            worker=lambda: request_fail2ban_reload(self.client, unban=unban),
            cli_hint=(
                "oyst-cli fail2ban reload --unban --confirm"
                if unban
                else "oyst-cli fail2ban reload --confirm"
            ),
        )

    def _on_jail_enable(self, name: str) -> None:
        run_in_thread(
            lambda: request_fail2ban_jail_enable(self.client, name),
            lambda r: self._mutation_done(r, f"Jail {name} enabled"),
            self._fail_status,
        )

    def _on_jail_disable(self, name: str) -> None:
        shield_firewall_ui.confirm_and_run(
            self,
            heading=f"Disable jail {name}?",
            body="The jail will stop protecting matching services until re-enabled.",
            action_id="disable",
            action_label="Disable",
            destructive=True,
            worker=lambda: request_fail2ban_jail_disable(self.client, name),
            cli_hint=f"oyst-cli fail2ban jail-control disable {name} --confirm",
        )

    def _on_unban_entry(self, row: Adw.EntryRow, *_args: object) -> None:
        ip = row.get_text().strip()
        if ip:
            self._on_unban_ip(ip, jail=None)
            row.set_text("")

    def _on_unban_ip(self, ip: str, jail: str | None) -> None:
        shield_firewall_ui.confirm_and_run(
            self,
            heading="Unban IP?",
            body=f"Unban {ip}" + (f" from {jail}" if jail else ""),
            action_id="unban",
            action_label="Unban",
            destructive=True,
            worker=lambda: request_fail2ban_unban(self.client, ip, jail=jail),
            cli_hint=f"oyst-cli fail2ban unban {ip} --confirm",
        )

    def _mutation_done(self, result: dict[str, Any], ok_msg: str) -> bool:
        if result.get("ok"):
            self._set_status(ok_msg)
            self.refresh()
        else:
            show_command_dialog(
                self._window,
                heading="Action failed",
                body=str(result.get("message") or "failed"),
            )
        return False

    # Used by shield_firewall_ui dialogs
    def apply_ufw_rule(
        self,
        action: str,
        *,
        port: str,
        proto: str,
        from_addr: str | None,
        force_lockout_risk: bool = False,
    ) -> None:
        run_in_thread(
            lambda: request_firewall_ufw_rule(
                self.client,
                action,
                port=port,
                proto=proto,
                from_addr=from_addr,
                force_lockout_risk=force_lockout_risk,
            ),
            lambda r: self._mutation_done(r, f"UFW {action} applied"),
            self._fail_status,
        )

    def apply_firewalld_port(self, action: str, port_spec: str) -> None:
        run_in_thread(
            lambda: request_firewall_firewalld_port(self.client, action, port_spec),
            lambda r: self._mutation_done(r, f"firewalld {action} queued — reload to apply"),
            self._fail_status,
        )

    def apply_firewalld_service(self, action: str, service: str) -> None:
        run_in_thread(
            lambda: request_firewall_firewalld_service(self.client, action, service),
            lambda r: self._mutation_done(r, f"firewalld {action} queued — reload to apply"),
            self._fail_status,
        )

    def apply_ufw_default(self, direction: str, policy: str, *, force: bool) -> None:
        run_in_thread(
            lambda: request_firewall_ufw_default(
                self.client,
                direction,
                policy,
                force_lockout_risk=force,
            ),
            lambda r: self._mutation_done(r, f"Default {direction}={policy}"),
            self._fail_status,
        )
