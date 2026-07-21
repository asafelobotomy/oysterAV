"""First-time setup wizard."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets import setup_wizard_actions as actions
from oysterav.gui.widgets import setup_wizard_auto as auto_actions
from oysterav.gui.widgets import setup_wizard_harden as harden_actions
from oysterav.gui.widgets.common import make_button, run_in_thread
from oysterav.gui.widgets.schedule_ui import (
    format_timer_status,
    timer_is_present,
)
from oysterav.gui.widgets.packs import PackListWidget
from oysterav.gui.widgets.setup_wizard_pages import build_pages
from oysterav.gui.widgets.setup_wizard_text import (
    PAGE_TITLES,
    format_check_summary,
    format_ready_checklist,
    schedule_timer_button_label,
    should_show_wizard,
)

__all__ = [
    "PAGE_TITLES",
    "SetupWizard",
    "format_check_summary",
    "format_ready_checklist",
    "schedule_timer_button_label",
    "should_show_wizard",
]


class SetupWizard:
    welcome_status: Gtk.Label
    auto_install_btn: Gtk.Button
    check_spinner: Gtk.Spinner
    check_label: Gtk.Label
    runtime_status_label: Gtk.Label
    install_warning: Adw.Banner
    pack_list: PackListWidget
    bootstrap_label: Gtk.Label
    bootstrap_primary_btn: Gtk.Button
    bootstrap_secondary_btn: Gtk.Button
    auto_quarantine: Adw.SwitchRow
    auto_recipe_switches: dict[str, Adw.SwitchRow]
    wizard_sched_profile: Adw.ComboRow
    wizard_sched_frequency: Adw.ComboRow
    wizard_sched_time: Adw.EntryRow
    schedule_label: Gtk.Label
    schedule_btn: Gtk.Button
    enable_firewall_row: Adw.SwitchRow
    harden_switches: dict[str, Adw.SwitchRow]
    harden_label: Gtk.Label
    harden_btn: Gtk.Button
    ready_summary: Gtk.Label

    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window,
        on_complete: Callable[[], None] | None = None,
        on_changed: Callable[[], None] | None = None,
        on_navigate: Callable[[str], None] | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self._parent_window = window
        self._on_complete = on_complete
        self._on_changed = on_changed
        self._on_navigate = on_navigate
        self._on_status = on_status
        self._packs: list[dict[str, Any]] = []
        self._setup: dict[str, Any] = {}
        self._dismissed = False
        self._current = 0
        self._doctor_running = False
        self._doctor_done = False
        self._install_skipped = False
        self._full_mode = self._detect_full_mode(client)
        self._bootstrap_busy = False
        self._auto_install_busy = False
        self._bootstrap_ran = False
        self._harden_ran = False
        self._harden_busy = False
        self._schedule_installed = False
        self._finish_pending = False

        self.dialog = Adw.Window()
        self.dialog.set_title("oysterAV Setup")
        self.dialog.set_transient_for(window)
        self.dialog.set_modal(True)
        self.dialog.set_default_size(860, 580)

        self._build_shell()
        build_pages(self)

    @property
    def assistant(self) -> Adw.Window:
        """Parent window for modal dialogs (replaces deprecated Gtk.Assistant)."""
        return self.dialog

    @staticmethod
    def _detect_full_mode(client: OystClient) -> bool:
        try:
            config = client.config_get()
            if isinstance(config, dict):
                runtime = config.get("runtime", {})
                if isinstance(runtime, dict):
                    mode = runtime.get("mode", "full")
                    return str(mode) == "full"
        except RuntimeError:
            pass
        return True

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _emit_changed(self) -> None:
        if self._on_changed:
            self._on_changed()

    def _selected_schedule(self) -> tuple[str, str, str]:
        profiles = ["quick", "full", "integrity", "suite"]
        freqs = ["hourly", "daily", "weekly"]
        p_idx = int(self.wizard_sched_profile.get_selected())
        f_idx = int(self.wizard_sched_frequency.get_selected())
        profile = profiles[p_idx] if 0 <= p_idx < len(profiles) else "quick"
        frequency = freqs[f_idx] if 0 <= f_idx < len(freqs) else "daily"
        at_time = self.wizard_sched_time.get_text().strip() or "02:00"
        return profile, frequency, at_time

    def _apply_schedule_ui(self, status: dict[str, Any]) -> None:
        present = timer_is_present(status)
        self._schedule_installed = present
        self.schedule_label.set_text(format_timer_status(status))
        profile, frequency, _at = self._selected_schedule()
        self.schedule_btn.set_label(
            schedule_timer_button_label(
                present=present,
                profile=profile,
                frequency=frequency,
            ),
        )
        self._refresh_ready_summary()

    def _refresh_ready_summary(self) -> None:
        if not hasattr(self, "ready_summary"):
            return
        self.ready_summary.set_text(
            format_ready_checklist(
                self._setup,
                bootstrap_ran=self._bootstrap_ran,
                schedule_installed=self._schedule_installed,
                auto_quarantine=self.auto_quarantine.get_active(),
                full_mode=self._full_mode,
                harden_ran=self._harden_ran,
            ),
        )

    def _build_shell(self) -> None:
        header = Adw.HeaderBar()
        self._cancel_btn = make_button("Cancel")
        self._cancel_btn.connect("clicked", self._on_cancel_clicked)
        header.pack_start(self._cancel_btn)

        self._back_btn = make_button("Back")
        self._back_btn.connect("clicked", self._on_back_clicked)
        header.pack_start(self._back_btn)

        self._next_btn = make_button("Next", suggested=True)
        self._next_btn.connect("clicked", self._on_next_clicked)
        header.pack_end(self._next_btn)

        self._sidebar = Gtk.ListBox()
        self._sidebar.set_size_request(180, -1)
        self._sidebar.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._sidebar.add_css_class("navigation-sidebar")
        for title in PAGE_TITLES:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label=title, xalign=0, margin_start=12, margin_end=12))
            row.set_selectable(False)
            row.set_activatable(False)
            self._sidebar.append(row)

        self._stack = Gtk.Stack()
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True)
        paned.set_start_child(self._sidebar)
        paned.set_end_child(self._stack)
        paned.set_shrink_start_child(False)
        paned.set_shrink_end_child(False)
        paned.set_resize_start_child(False)
        paned.set_resize_end_child(True)
        paned.set_position(190)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        body.append(paned)
        body.set_vexpand(True)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(body)
        self.dialog.set_content(toolbar)

    def _wrap_scrolled(self, content: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(content)
        scroll.set_vexpand(True)
        return scroll

    def present(self) -> None:
        self.dialog.present()
        GLib.idle_add(self._after_present)

    def _after_present(self) -> bool:
        self._load_preferences()
        actions.run_doctor(self)
        self._refresh_schedule_status()
        return False

    def _load_preferences(self) -> None:
        try:
            val = self.client.config_get("quarantine.auto")
            self.auto_quarantine.set_active(str(val).lower() in ("true", "1", "yes"))
        except RuntimeError as exc:
            self._set_status(f"Could not load preferences: {exc}")

    def _on_recheck_clicked(self, *_args: object) -> None:
        actions.run_doctor(self)

    def _on_packs_changed(self) -> None:
        actions.on_packs_changed(self)

    def _refresh_install_gate(self) -> None:
        missing = list(self._setup.get("missing_required") or [])
        reveal = bool(missing) and not self._install_skipped
        self.install_warning.set_title(
            f"Required packs still missing: {', '.join(missing)}. "
            "Continue anyway lets you finish setup; the wizard will not keep "
            "reopening for those packs.",
        )
        self.install_warning.set_button_label("Continue anyway")
        self.install_warning.set_revealed(reveal)

    def _on_schedule_prefs_changed(self) -> None:
        profile, frequency, _at = self._selected_schedule()
        self.schedule_btn.set_label(
            schedule_timer_button_label(
                present=self._schedule_installed,
                profile=profile,
                frequency=frequency,
            ),
        )

    def _refresh_schedule_status(self) -> None:
        def done(status: dict[str, Any]) -> bool:
            self._apply_schedule_ui(status)
            return False

        run_in_thread(lambda: self.client.schedule_status(), done, lambda _m: False)

    def _can_advance(self) -> bool:
        if self._current == 1:
            if not self._doctor_done or self._doctor_running:
                return False
            missing = list(self._setup.get("missing_required") or [])
            return not missing or self._install_skipped
        return True

    def _go_to_page(self, index: int) -> None:
        self._current = max(0, min(index, len(PAGE_TITLES) - 1))
        self._stack.set_visible_child_name(f"page-{self._current}")
        row = self._sidebar.get_row_at_index(self._current)
        if row is not None:
            self._sidebar.select_row(row)
        if self._current == len(PAGE_TITLES) - 1:
            self._refresh_ready_summary()
        self._update_nav()

    def _update_nav(self) -> None:
        busy = (
            self._auto_install_busy
            or self._bootstrap_busy
            or self._harden_busy
            or self._finish_pending
        )
        self._back_btn.set_sensitive(self._current > 0 and not busy)
        on_last = self._current == len(PAGE_TITLES) - 1
        self._next_btn.set_label("Finish" if on_last else "Next")
        self._next_btn.set_sensitive((self._can_advance() or on_last) and not busy)
        self._cancel_btn.set_sensitive(not busy)
        self.auto_install_btn.set_sensitive(not self._auto_install_busy)
        if hasattr(self, "harden_btn"):
            self.harden_btn.set_sensitive(not self._harden_busy)

    def _on_back_clicked(self, *_args: object) -> None:
        if self._current > 0:
            self._go_to_page(self._current - 1)

    def _on_next_clicked(self, *_args: object) -> None:
        if self._current == len(PAGE_TITLES) - 1:
            actions.finish_setup(self, mark_complete=True)
            return
        if not self._can_advance():
            return
        self._go_to_page(self._current + 1)

    def _on_cancel_clicked(self, *_args: object) -> None:
        if self._auto_install_busy:
            return
        actions.finish_setup(self, mark_complete=False)

    def _on_auto_install(self, *_args: object) -> None:
        auto_actions.on_auto_install(self, *_args)

    def _on_install_skip(self, *_args: object) -> None:
        actions.on_install_skip(self, *_args)

    def _on_full_bootstrap(self, *_args: object) -> None:
        actions.on_full_bootstrap(self, *_args)

    def _on_bootstrap_only(self, *_args: object) -> None:
        actions.on_bootstrap_only(self, *_args)

    def _on_schedule_install(self, *_args: object) -> None:
        actions.on_schedule_install(self, *_args)

    def _on_apply_harden(self, *_args: object) -> None:
        harden_actions.on_apply_harden(self, *_args)

    def _on_open_scan(self, *_args: object) -> None:
        if self._on_navigate:
            self._on_navigate("scan")
        actions.finish_setup(self, mark_complete=True)
