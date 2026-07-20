"""Scan tab — configure orchestrated scans and review per-pack results."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import ScanProfile
from oysterav.gui.scan_helpers import PackCardState, expected_packs_for_profile
from oysterav.gui.widgets.common import (
    PreferencesGroup,
    StatusCard,
    bind_string_combo_row,
    make_button,
    make_scrolled_page,
    make_section_heading,
    run_in_thread,
)
from oysterav.gui.widgets import scan_job_ui, scan_path_ui
from oysterav.gui.widgets.scan_const import (
    COLUMN_BREAKPOINT,
    CUSTOM_PACK_CHOICES,
    PATH_PRESETS,
    PROFILE_LABELS,
    RESULT_PACKS,
    SCAN_PROFILES,
)


class ScanPage:
    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window | None = None,
        on_status: Callable[[str], None] | None = None,
        on_scan_complete: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self._window = window
        self._on_status = on_status
        self._on_scan_complete = on_scan_complete
        self._scanning = False
        self._custom_path: str | None = None
        self._width_handler_id = 0
        self._poll_id = 0
        self._last_scan: dict[str, Any] | None = None
        self._expected_packs: list[str] = []
        self._card_states: dict[str, PackCardState] = {
            name: PackCardState.IDLE for name in RESULT_PACKS
        }
        self._pack_findings: dict[str, list[dict[str, Any]]] = {name: [] for name in RESULT_PACKS}
        self._pack_errors: dict[str, str] = {name: "" for name in RESULT_PACKS}

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        left.set_hexpand(True)
        left.set_size_request(280, -1)

        left.append(PreferencesGroup("Scan"))

        self.scan_btn = make_button("Run scan", suggested=True)
        self.scan_btn.set_halign(Gtk.Align.START)
        self.scan_btn.connect("clicked", self._on_start_scan)
        left.append(self.scan_btn)

        self.cancel_btn = make_button("Cancel scan")
        self.cancel_btn.set_halign(Gtk.Align.START)
        self.cancel_btn.set_visible(False)
        self.cancel_btn.connect("clicked", lambda *a: scan_job_ui.on_cancel_scan(self, *a))
        left.append(self.cancel_btn)

        self.path_controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        path_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        path_buttons.set_homogeneous(False)
        self.browse_folder_btn = make_button("Browse folder…")
        self.browse_folder_btn.connect(
            "clicked", lambda *a: scan_path_ui.on_browse_folder(self, *a)
        )
        self.browse_file_btn = make_button("Browse file…")
        self.browse_file_btn.connect("clicked", lambda *a: scan_path_ui.on_browse_file(self, *a))
        self.clear_path_btn = make_button("Clear path")
        self.clear_path_btn.connect("clicked", lambda *a: scan_path_ui.on_clear_path(self, *a))
        self.clear_path_btn.set_visible(False)
        path_buttons.append(self.browse_folder_btn)
        path_buttons.append(self.browse_file_btn)
        path_buttons.append(self.clear_path_btn)
        self.path_controls.append(path_buttons)

        self.path_label = Gtk.Label(label="", xalign=0)
        self.path_label.add_css_class("dim-label")
        self.path_label.set_wrap(True)
        self.path_controls.append(self.path_label)
        left.append(self.path_controls)

        options_group = PreferencesGroup("")
        profile_row = Adw.ComboRow(title="Scan profile")
        profile_labels = [PROFILE_LABELS[p] for p in SCAN_PROFILES]
        bind_string_combo_row(profile_row, profile_labels)
        profile_row.connect(
            "notify::selected",
            lambda *a: scan_path_ui.on_profile_changed(self, *a),
        )
        options_group.add(profile_row)
        self.profile_row = profile_row

        self.path_row = Adw.ComboRow(title="Scan target")
        bind_string_combo_row(self.path_row, [label for label, _ in PATH_PRESETS])
        self.path_row.connect(
            "notify::selected", lambda *a: scan_path_ui.on_path_preset_changed(self, *a)
        )
        options_group.add(self.path_row)

        self.packs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.packs_box.set_visible(False)
        packs_label = make_section_heading("Custom packs")
        self.packs_box.append(packs_label)
        self._pack_checks: dict[str, Gtk.CheckButton] = {}
        for pack_name in CUSTOM_PACK_CHOICES:
            check = Gtk.CheckButton(label=pack_name)
            check.set_active(pack_name == "clamav")
            self._pack_checks[pack_name] = check
            self.packs_box.append(check)

        options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        options_box.append(options_group)
        options_box.append(self.packs_box)
        left.append(options_box)

        self.integrity_note = Gtk.Label(
            label="System-wide integrity tools; paths ignored",
            xalign=0,
        )
        self.integrity_note.add_css_class("dim-label")
        self.integrity_note.set_wrap(True)
        self.integrity_note.set_visible(False)
        left.append(self.integrity_note)

        right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        right.set_hexpand(True)
        right.set_size_request(280, -1)

        progress_heading = PreferencesGroup("Scan Progress")
        right.append(progress_heading)
        progress_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        progress_box.set_margin_start(12)
        progress_box.set_margin_end(12)
        progress_box.set_margin_bottom(8)
        self.status_label = Gtk.Label(label="Ready to scan", xalign=0)
        self.status_label.add_css_class("dim-label")
        progress_box.append(self.status_label)
        self.progress = Gtk.ProgressBar()
        self.progress.set_visible(False)
        progress_box.append(self.progress)
        self.result_banner = Adw.Banner(title="")
        self.result_banner.set_revealed(False)
        progress_box.append(self.result_banner)
        right.append(progress_box)

        results_group = PreferencesGroup("Scan Results")
        right.append(results_group)

        self._pack_cards: dict[str, StatusCard] = {}
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        row1.set_homogeneous(True)
        row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        row2.set_homogeneous(True)

        def _bind(pack_name: str) -> Callable[[], None]:
            return lambda: scan_job_ui.on_pack_card_activated(self, pack_name)

        for name in ("clamav", "maldet", "rkhunter"):
            card = StatusCard(name, on_activate=_bind(name))
            self._pack_cards[name] = card
            row1.append(card)
        for name in ("chkrootkit", "unhide", "lynis"):
            card = StatusCard(name, on_activate=_bind(name))
            self._pack_cards[name] = card
            row2.append(card)
        cards_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        cards_box.append(row1)
        cards_box.append(row2)
        right.append(cards_box)
        scan_job_ui.reset_cards_idle(self)

        self._columns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        self._columns.set_homogeneous(True)
        self._columns.append(left)
        self._columns.append(right)
        self._columns.connect("map", self._on_columns_mapped)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(1100)
        clamp.set_tightening_threshold(720)
        clamp.set_child(self._columns)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        root.set_margin_start(12)
        root.set_margin_end(12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)
        root.append(clamp)

        self.widget = make_scrolled_page(root)
        scan_path_ui.sync_profile_path_ui(self)
        scan_path_ui.update_path_label(self)

    def set_window(self, window: Gtk.Window) -> None:
        if self._window is not None and self._width_handler_id:
            self._window.disconnect(self._width_handler_id)
            self._width_handler_id = 0
        self._window = window
        self._width_handler_id = window.connect(
            "notify::default-width",
            self._on_window_geometry,
        )
        window.connect("notify::maximized", self._on_window_geometry)
        GLib.idle_add(self._reflow_columns)

    def refresh(self) -> None:
        """Apply scan.profile default from config when not mid-scan."""
        if self._scanning:
            return

        def worker() -> dict[str, Any]:
            cfg = self.client.config_get()
            return cfg if isinstance(cfg, dict) else {}

        def done(cfg: dict[str, Any]) -> bool:
            if self._scanning:
                return False
            scan = cfg.get("scan") if isinstance(cfg, dict) else None
            profile = "quick"
            if isinstance(scan, dict):
                profile = str(scan.get("profile") or "quick")
            for idx, item in enumerate(SCAN_PROFILES):
                if item.value == profile:
                    self.profile_row.set_selected(idx)
                    break
            scan_path_ui.on_profile_changed(self)
            return False

        def failed(_message: str) -> bool:
            return False

        run_in_thread(worker, done, failed)

    def _on_columns_mapped(self, *_args: object) -> None:
        GLib.idle_add(self._reflow_columns)

    def _on_window_geometry(self, *_args: object) -> None:
        GLib.idle_add(self._reflow_columns)

    def _reflow_columns(self) -> bool:
        width = self._columns.get_width()
        if width < 2 and self._window is not None:
            width = self._window.get_width()
        if width < 2:
            return False
        desired = (
            Gtk.Orientation.VERTICAL if width < COLUMN_BREAKPOINT else Gtk.Orientation.HORIZONTAL
        )
        if self._columns.get_orientation() != desired:
            self._columns.set_orientation(desired)
        return False

    def _set_status(self, text: str) -> None:
        self.status_label.set_text(text)
        if self._on_status:
            self._on_status(text)

    def _profile(self) -> ScanProfile:
        idx = int(self.profile_row.get_selected())
        if idx < 0 or idx >= len(SCAN_PROFILES):
            return ScanProfile.QUICK
        return SCAN_PROFILES[idx]

    def _profile_value(self) -> str:
        return str(self._profile().value)

    def _is_integrity(self) -> bool:
        return self._profile() is ScanProfile.INTEGRITY

    def _on_start_scan(self, *_args: object) -> None:
        if self._scanning:
            return
        if not self._is_integrity() and self.path_row.get_selected() == 3 and not self._custom_path:
            self._set_status("Choose a folder or file for Custom target")
            return

        packs: list[str] | None = None
        if self._profile() is ScanProfile.CUSTOM:
            packs = scan_path_ui.selected_custom_packs(self)
            if not packs:
                self._set_status("Select at least one pack for a custom scan")
                return
            unknown = [p for p in packs if p not in CUSTOM_PACK_CHOICES]
            if unknown:
                self._set_status(f"Unknown packs: {', '.join(unknown)}")
                return

        profile = self._profile()
        self._expected_packs = expected_packs_for_profile(profile, packs)
        self._scanning = True
        self._last_scan = None
        scan_job_ui.set_scan_controls_sensitive(self, False)
        scan_job_ui.prepare_cards_for_scan(self, self._expected_packs)
        self.result_banner.set_revealed(False)
        self._set_status("Starting scan…")
        scan_job_ui.start_poll(self)

        profile_value = self._profile_value()
        paths = scan_path_ui.resolved_paths(self)

        def worker() -> dict[str, Any]:
            return self.client.start_scan(
                profile=profile_value,
                paths=paths,
                packs=packs,
                quarantine=False,
            )

        run_in_thread(
            worker,
            lambda result: scan_job_ui.on_scan_done(self, result),
            lambda message: scan_job_ui.on_scan_failed(self, message),
        )
