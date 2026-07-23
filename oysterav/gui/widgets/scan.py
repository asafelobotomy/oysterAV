"""Scan tab — configure orchestrated scans and review per-pack results."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import uuid4

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import ScanProfile
from oyst_core.privilege import build_scan_privileged_plan
from oysterav.gui.scan_helpers import PackCardState, expected_packs_for_profile, pack_card_title
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
from oysterav.gui.widgets.privilege_confirm import confirm_privilege_plan
from oysterav.gui.widgets.scan_const import (
    CUSTOM_PACK_CHOICES,
    PATH_PRESETS,
    PROFILE_LABELS,
    RESULT_PACKS,
    SCAN_ACTION_INNER_GAP,
    SCAN_ACTIONS_TO_OPTIONS_GAP,
    SCAN_OPTIONS_TO_PROGRESS_GAP,
    SCAN_PAGE_MARGIN,
    SCAN_PROFILES,
    SCAN_PROGRESS_INNER_GAP,
    SCAN_PROGRESS_TO_RESULTS_GAP,
    SCAN_RESULTS_HEADING_GAP,
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
        self._poll_id = 0
        self._last_scan: dict[str, Any] | None = None
        self._expected_packs: list[str] = []
        self._job_percent = 0.0
        self._card_states: dict[str, PackCardState] = {
            name: PackCardState.IDLE for name in RESULT_PACKS
        }
        self._pack_findings: dict[str, list[dict[str, Any]]] = {name: [] for name in RESULT_PACKS}
        self._pack_errors: dict[str, str] = {name: "" for name in RESULT_PACKS}

        stack = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        stack.set_hexpand(True)

        actions_section = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=SCAN_ACTION_INNER_GAP,
        )
        actions_section.set_margin_bottom(SCAN_ACTIONS_TO_OPTIONS_GAP)

        self.scan_btn = make_button("Run scan", suggested=True)
        self.scan_btn.add_css_class("oyster-scan-run")
        self.scan_btn.set_halign(Gtk.Align.CENTER)
        self.scan_btn.connect("clicked", self._on_start_scan)
        actions_section.append(self.scan_btn)

        self.cancel_btn = make_button("Cancel scan")
        self.cancel_btn.set_halign(Gtk.Align.CENTER)
        self.cancel_btn.set_visible(False)
        self.cancel_btn.connect("clicked", lambda *a: scan_job_ui.on_cancel_scan(self, *a))
        actions_section.append(self.cancel_btn)

        self.path_controls = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=SCAN_ACTION_INNER_GAP,
        )
        path_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        path_buttons.set_homogeneous(False)
        path_buttons.set_halign(Gtk.Align.CENTER)
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

        self.path_label = Gtk.Label(label="", xalign=0.5)
        self.path_label.set_halign(Gtk.Align.CENTER)
        self.path_label.add_css_class("dim-label")
        self.path_label.set_wrap(True)
        self.path_controls.append(self.path_label)
        actions_section.append(self.path_controls)
        stack.append(actions_section)

        options_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        options_section.set_margin_bottom(SCAN_OPTIONS_TO_PROGRESS_GAP)

        options_group = PreferencesGroup("")
        options_group.add_css_class("oyster-scan-options")
        profile_row = Adw.ComboRow(title="Scan profile")
        profile_labels = [PROFILE_LABELS[p] for p in SCAN_PROFILES]
        bind_string_combo_row(profile_row, profile_labels, compact=True)
        profile_row.connect(
            "notify::selected",
            lambda *a: scan_path_ui.on_profile_changed(self, *a),
        )
        options_group.add(profile_row)
        self.profile_row = profile_row

        self.path_row = Adw.ComboRow(title="Scan target")
        bind_string_combo_row(
            self.path_row,
            [label for label, _ in PATH_PRESETS],
            compact=True,
        )
        self.path_row.connect(
            "notify::selected", lambda *a: scan_path_ui.on_path_preset_changed(self, *a)
        )
        options_group.add(self.path_row)
        options_section.append(options_group)

        self.integrity_note = Gtk.Label(
            label="System-wide integrity tools; paths ignored",
            xalign=0.5,
        )
        self.integrity_note.set_halign(Gtk.Align.CENTER)
        self.integrity_note.add_css_class("dim-label")
        self.integrity_note.set_wrap(True)
        self.integrity_note.set_visible(False)
        options_section.append(self.integrity_note)
        stack.append(options_section)

        progress_section = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            spacing=SCAN_PROGRESS_INNER_GAP,
        )
        progress_section.set_margin_bottom(SCAN_PROGRESS_TO_RESULTS_GAP)
        progress_heading = make_section_heading("Scan Progress")
        progress_heading.add_css_class("oyster-scan-section")
        progress_heading.set_xalign(0.5)
        progress_heading.set_halign(Gtk.Align.CENTER)
        progress_section.append(progress_heading)
        self.status_label = Gtk.Label(label="Ready to scan", xalign=0.5)
        self.status_label.set_halign(Gtk.Align.CENTER)
        self.status_label.add_css_class("dim-label")
        progress_section.append(self.status_label)
        self.progress = Gtk.ProgressBar()
        self.progress.set_visible(False)
        progress_section.append(self.progress)
        self.result_banner = Adw.Banner(title="")
        self.result_banner.set_revealed(False)
        progress_section.append(self.result_banner)
        stack.append(progress_section)

        results_section = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        results_heading = make_section_heading("Scan Results")
        results_heading.add_css_class("oyster-scan-section")
        results_heading.set_xalign(0.5)
        results_heading.set_halign(Gtk.Align.CENTER)
        results_section.append(results_heading)

        self._pack_cards: dict[str, StatusCard] = {}
        self._pack_checks: dict[str, Gtk.CheckButton] = {}
        row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        row1.set_homogeneous(True)
        row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        row2.set_homogeneous(True)

        def _bind(pack_name: str) -> Callable[[], None]:
            return lambda: scan_job_ui.on_pack_card_activated(self, pack_name)

        def _on_pack_toggled(*_a: object) -> None:
            scan_job_ui.sync_result_cards_for_profile(self)

        for name in ("clamav", "maldet", "rkhunter"):
            card = StatusCard(
                pack_card_title(name),
                on_activate=_bind(name),
                compact=True,
                selectable=True,
            )
            assert card.select_check is not None
            card.select_check.set_active(name == "clamav")
            card.select_check.connect("toggled", _on_pack_toggled)
            self._pack_checks[name] = card.select_check
            self._pack_cards[name] = card
            row1.append(card)
        for name in ("chkrootkit", "unhide", "lynis"):
            card = StatusCard(
                pack_card_title(name),
                on_activate=_bind(name),
                compact=True,
                selectable=True,
            )
            assert card.select_check is not None
            card.select_check.set_active(False)
            card.select_check.connect("toggled", _on_pack_toggled)
            self._pack_checks[name] = card.select_check
            self._pack_cards[name] = card
            row2.append(card)
        cards_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        cards_box.set_margin_top(SCAN_RESULTS_HEADING_GAP)
        cards_box.append(row1)
        cards_box.append(row2)
        results_section.append(cards_box)
        stack.append(results_section)
        scan_job_ui.reset_cards_idle(self)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(760)
        clamp.set_tightening_threshold(640)
        clamp.set_child(stack)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        root.set_margin_start(SCAN_PAGE_MARGIN)
        root.set_margin_end(SCAN_PAGE_MARGIN)
        root.set_margin_top(SCAN_PAGE_MARGIN)
        root.set_margin_bottom(SCAN_PAGE_MARGIN)
        root.append(clamp)

        self.widget = make_scrolled_page(root)
        scan_path_ui.sync_profile_path_ui(self)
        scan_path_ui.update_path_label(self)

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

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
        expected = expected_packs_for_profile(profile, packs)
        job_id = str(uuid4())
        plan = build_scan_privileged_plan(expected, job_id=job_id)
        confirm_privilege_plan(
            self._window,
            plan,
            on_continue=lambda: self._launch_scan(packs, expected, job_id),
            continue_label="Continue",
        )

    def _launch_scan(
        self,
        packs: list[str] | None,
        expected: list[str],
        job_id: str,
    ) -> None:
        self._expected_packs = expected
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
                job_id=job_id,
            )

        run_in_thread(
            worker,
            lambda result: scan_job_ui.on_scan_done(self, result),
            lambda message: scan_job_ui.on_scan_failed(self, message),
        )
