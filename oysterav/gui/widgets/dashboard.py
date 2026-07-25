"""Dashboard tab — pressing posture at a glance."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.dashboard_helpers import DashboardCardModel, DashboardNav, build_dashboard_cards
from oysterav.gui.rpc_actions import (
    request_auth_status,
    request_firewall_status,
    request_services_status,
)
from oysterav.gui.widgets.common import (
    PreferencesGroup,
    StatusCard,
    format_relative_time,
    make_scrolled_page,
    make_status_badge,
    run_in_thread,
    show_command_dialog,
)

_CORE_IDS = (
    "protection",
    "definitions",
    "realtime",
    "last_scan",
    "quarantine",
    "host_shield",
)


class DashboardPage:
    def __init__(
        self,
        client: OystClient,
        *,
        on_navigate: Callable[..., None] | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self._on_navigate = on_navigate
        self._on_status = on_status
        self._window: Gtk.Window | None = None
        self._banner_navigate_settings = False
        self._card_nav: dict[str, DashboardNav | None] = {}

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_margin_start(12)
        root.set_margin_end(12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)

        self.banner = Adw.Banner(title="")
        self.banner.set_revealed(False)
        self.banner.connect("button-clicked", self._on_banner_clicked)
        root.append(self.banner)

        self._cards_column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.row1.set_homogeneous(True)
        self.row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.row2.set_homogeneous(True)
        self.row3 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.row3.set_homogeneous(True)
        self.row3.set_visible(False)
        self._cards_column.append(self.row1)
        self._cards_column.append(self.row2)
        self._cards_column.append(self.row3)
        root.append(self._cards_column)

        self._cards: dict[str, StatusCard] = {}
        titles = {
            "protection": "Protection",
            "definitions": "Definitions",
            "realtime": "Real-time",
            "last_scan": "Last scan",
            "quarantine": "Quarantine",
            "host_shield": "Host shield",
            "helper": "Helper",
        }
        for cid in _CORE_IDS:
            card = StatusCard(titles[cid], on_activate=self._make_activate(cid))
            self._cards[cid] = card
        self.row1.append(self._cards["protection"])
        self.row1.append(self._cards["definitions"])
        self.row1.append(self._cards["realtime"])
        self.row2.append(self._cards["last_scan"])
        self.row2.append(self._cards["quarantine"])
        self.row2.append(self._cards["host_shield"])

        self.helper_card = StatusCard("Helper", on_activate=self._make_activate("helper"))
        self.helper_card.set_visible(False)
        self.row3.append(self.helper_card)
        self._cards["helper"] = self.helper_card

        self.history_group = PreferencesGroup("Recent scans")
        self._history_rows: list[Adw.PreferencesRow] = []
        root.append(self.history_group)

        self.widget = make_scrolled_page(root)

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def _make_activate(self, card_id: str) -> Callable[[], None]:
        return lambda: self._on_card_activated(card_id)

    def _navigate(self, tab: str, **kwargs: Any) -> None:
        if self._on_navigate:
            self._on_navigate(tab, **kwargs)

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _on_banner_clicked(self, *_args: object) -> None:
        if self._banner_navigate_settings:
            self._navigate("settings", section="packs")
        self.banner.set_revealed(False)

    def _on_card_activated(self, card_id: str) -> None:
        nav = self._card_nav.get(card_id)
        if nav is None:
            return
        if nav.action == "ensure_clamd":
            self._ensure_clamd()
            return
        kwargs: dict[str, Any] = {}
        if nav.section:
            kwargs["section"] = nav.section
        if nav.job_id:
            kwargs["job_id"] = nav.job_id
        self._navigate(nav.tab, **kwargs)

    def refresh(self) -> None:
        run_in_thread(self._load_data, self._apply_data, self._apply_error)

    def _load_data(self) -> dict[str, Any]:
        status = self.client.status()
        assess = self.client.status_assess()
        history = self.client.history_list(limit=5)
        quarantine = self.client.quarantine_list()
        try:
            services = request_services_status(self.client)
        except Exception:  # noqa: BLE001 — dashboard stays usable
            services = {}
        try:
            firewall = request_firewall_status(self.client)
        except Exception:  # noqa: BLE001
            firewall = {}
        try:
            auth = request_auth_status(self.client)
        except Exception:  # noqa: BLE001
            auth = {}
        return {
            "status": status if isinstance(status, dict) else {},
            "assess": assess if isinstance(assess, dict) else {},
            "history": history if isinstance(history, list) else [],
            "quarantine_count": len(quarantine) if isinstance(quarantine, list) else 0,
            "services": services if isinstance(services, dict) else {},
            "firewall": firewall if isinstance(firewall, dict) else {},
            "auth": auth if isinstance(auth, dict) else {},
        }

    def _apply_data(self, data: dict[str, Any]) -> bool:
        status = data.get("status") or {}
        assess = data.get("assess") or {}
        history = data.get("history") or []
        if not isinstance(history, list):
            history = []

        missing_required = any(
            issue.get("code") == "missing_required_packs"
            for issue in assess.get("issues", [])
            if isinstance(issue, dict)
        )
        title = str(assess.get("banner_title", "System protected"))
        body = str(assess.get("banner_body", ""))
        show = bool(assess.get("show_banner", False))
        self._banner_navigate_settings = missing_required
        self.banner.set_title(title)
        if show:
            self.banner.set_button_label("Open Settings" if missing_required else "Dismiss")
        self.banner.set_revealed(show)
        if show and body:
            self.banner.set_title(f"{title} — {body}")
        elif not show:
            self.banner.set_title(title)

        services_raw = data.get("services")
        firewall_raw = data.get("firewall")
        auth_raw = data.get("auth")
        services: dict[str, Any] = services_raw if isinstance(services_raw, dict) else {}
        firewall: dict[str, Any] = firewall_raw if isinstance(firewall_raw, dict) else {}
        auth: dict[str, Any] = auth_raw if isinstance(auth_raw, dict) else {}
        status_dict: dict[str, Any] = status if isinstance(status, dict) else {}
        models = build_dashboard_cards(
            status=status_dict,
            history=[h for h in history if isinstance(h, dict)],
            quarantine_count=int(data.get("quarantine_count") or 0),
            services=services,
            firewall=firewall,
            auth=auth,
        )
        self._apply_card_models(models)
        self._populate_history([h for h in history if isinstance(h, dict)])
        return False

    def _apply_card_models(self, models: list[DashboardCardModel]) -> None:
        by_id = {m.id: m for m in models}
        self._card_nav.clear()
        for cid in _CORE_IDS:
            model = by_id.get(cid)
            if model is None:
                continue
            self._cards[cid].set_values(
                model.value,
                model.description,
                css_class=model.css_class,
            )
            self._card_nav[cid] = model.nav

        helper = by_id.get("helper")
        if helper is None:
            self.helper_card.set_visible(False)
            self.row3.set_visible(False)
            self._card_nav.pop("helper", None)
        else:
            self.helper_card.set_values(
                helper.value,
                helper.description,
                css_class=helper.css_class,
            )
            self.helper_card.set_visible(True)
            self.row3.set_visible(True)
            self._card_nav["helper"] = helper.nav

    def _apply_error(self, message: str) -> bool:
        self._set_status(f"Could not reach the backend: {message}")
        return False

    def _clear_history_rows(self) -> None:
        for row in self._history_rows:
            self.history_group.remove(row)
        self._history_rows.clear()

    def _populate_history(self, history: list[dict[str, Any]]) -> None:
        self._clear_history_rows()
        if not history:
            empty = Adw.ActionRow(title="No scans yet")
            empty.set_subtitle("Run a scan from the Scan tab.")
            self.history_group.add(empty)
            self._history_rows.append(empty)
            return
        for item in history:
            row = Adw.ActionRow()
            profile = item.get("profile", "?")
            started = format_relative_time(item.get("started_at"))
            state = str(item.get("state") or "completed")
            clean = bool(item.get("clean"))
            findings = int(item.get("findings_count") or 0)
            row.set_title(f"{str(profile).capitalize()} scan")
            row.set_subtitle(started)
            if state == "cancelled":
                badge_text, badge_class = "Cancelled", "warning"
            elif not clean or findings > 0:
                n = findings or 1
                badge_text = "1 threat" if n == 1 else f"{n} threats"
                badge_class = "error"
            elif item.get("has_errors"):
                badge_text, badge_class = "Errors", "warning"
            else:
                badge_text, badge_class = "Clean", "success"
            row.add_suffix(make_status_badge(badge_text, badge_class))
            job_id = str(item.get("job_id") or "")
            if job_id:
                row.set_activatable(True)
                row.connect(
                    "activated",
                    lambda _r, jid=job_id: self._navigate("reports", job_id=jid),
                )
            self.history_group.add(row)
            self._history_rows.append(row)

    def _ensure_clamd(self) -> None:
        self._set_status("Starting ClamAV daemon…")

        def done(result: dict[str, Any]) -> bool:
            if result.get("ok"):
                self._set_status("ClamAV daemon started")
            else:
                self._set_status(f"ClamAV daemon: {result.get('message', 'failed')}")
                if self._window:
                    show_command_dialog(
                        self._window,
                        heading="Could not start clamd",
                        body=str(result.get("message", "unknown error")),
                        copy_text="oyst-cli clamav clamd ensure",
                    )
            self.refresh()
            return False

        run_in_thread(self.client.clamav_clamd_ensure, done, self._apply_error)
