"""Dashboard tab — system posture at a glance."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import (
    PreferencesGroup,
    StatusCard,
    format_relative_time,
    format_signature_age,
    make_scrolled_page,
    make_status_badge,
    run_in_thread,
    show_command_dialog,
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

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_margin_start(12)
        root.set_margin_end(12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)

        self.banner = Adw.Banner(title="")
        self.banner.set_revealed(False)
        self.banner.connect("button-clicked", self._on_banner_clicked)
        root.append(self.banner)

        cards = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        cards.set_homogeneous(True)
        self.clam_card = StatusCard(
            "ClamAV",
            on_activate=self._on_clam_card_clicked,
        )
        self.sig_card = StatusCard("Signatures")
        self.scan_card = StatusCard(
            "Last Scan",
            on_activate=lambda: self._navigate("scan"),
        )
        self.vault_card = StatusCard(
            "Quarantine",
            on_activate=lambda: self._navigate("quarantine"),
        )
        for card in (self.clam_card, self.sig_card, self.scan_card, self.vault_card):
            cards.append(card)
        root.append(cards)

        self.history_group = PreferencesGroup("Recent scans")
        self._history_rows: list[Adw.PreferencesRow] = []
        root.append(self.history_group)

        self.widget = make_scrolled_page(root)
        self._banner_navigate_settings = False
        self._clamd_running = False
        self._window: Gtk.Window | None = None

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def _navigate(self, tab: str, **kwargs: Any) -> None:
        if self._on_navigate:
            self._on_navigate(tab, **kwargs)

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _on_banner_clicked(self, *_args: object) -> None:
        if self._banner_navigate_settings:
            # Missing required packs → Security packs section.
            self._navigate("settings", section="packs")
        self.banner.set_revealed(False)

    def refresh(self) -> None:
        run_in_thread(
            self._load_data,
            self._apply_data,
            self._apply_error,
        )

    def _load_data(self) -> dict[str, Any]:
        status = self.client.status()
        assess = self.client.status_assess()
        history = self.client.history_list(limit=5)
        quarantine = self.client.quarantine_list()
        return {
            "status": status,
            "assess": assess,
            "history": history,
            "quarantine_count": len(quarantine),
        }

    def _apply_data(self, data: dict[str, Any]) -> bool:
        status = data["status"]
        assess = data.get("assess", {})

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
            label = "Open Settings" if missing_required else "Dismiss"
            self.banner.set_button_label(label)
        self.banner.set_revealed(show)
        if show and body:
            self.banner.set_title(f"{title} — {body}")
        elif not show:
            self.banner.set_title(title)

        clamd = status.get("clamd_running", False)
        self._clamd_running = bool(clamd)
        self.clam_card.set_values(
            "Running" if clamd else "Stopped",
            "Tap to start clamd" if not clamd else "On-demand scanning engine",
            css_class="success" if clamd else "warning",
        )

        sig_text, sig_class = format_signature_age(status.get("signature_age_hours"))
        self.sig_card.set_values(sig_text, "ClamAV definition age", css_class=sig_class)

        last_scan = status.get("last_scan_at")
        self.scan_card.set_values(
            format_relative_time(last_scan),
            "Most recent completed scan",
        )

        count = data["quarantine_count"]
        self.vault_card.set_values(
            str(count),
            "item in vault" if count == 1 else "items in vault",
            css_class="error" if count else "success",
        )

        self._populate_history(data["history"])
        return False

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
            row.set_title(f"{profile.capitalize()} scan")
            row.set_subtitle(started)
            if state == "cancelled":
                badge_text, badge_class = "Cancelled", "warning"
            elif not clean or findings > 0:
                badge_text, badge_class = f"{findings or 1} threat(s)", "error"
            elif item.get("has_errors"):
                badge_text, badge_class = "Errors", "warning"
            else:
                badge_text, badge_class = "Clean", "success"
            badge = make_status_badge(badge_text, badge_class)
            row.add_suffix(badge)
            job_id = str(item.get("job_id") or "")
            if job_id:
                row.set_activatable(True)
                row.connect(
                    "activated",
                    lambda _r, jid=job_id: self._navigate("reports", job_id=jid),
                )
            self.history_group.add(row)
            self._history_rows.append(row)

    def _on_clam_card_clicked(self) -> None:
        if self._clamd_running:
            return
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
