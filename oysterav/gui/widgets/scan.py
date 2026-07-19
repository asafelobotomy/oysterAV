"""Scan tab — configure orchestrated scans and review per-pack results."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import PROFILE_PATHS, ScanProfile
from oysterav.gui.rpc_actions import request_job_cancel, request_job_status
from oysterav.gui.scan_helpers import (
    PackCardState,
    expected_packs_for_profile,
    pack_result_summary,
)
from oysterav.gui.widgets.common import (
    PreferencesGroup,
    StatusCard,
    bind_string_combo_row,
    default_paths_for_profile,
    make_button,
    make_scrolled_page,
    make_section_heading,
    run_in_thread,
)
from oysterav.gui.widgets.scan_result_dialog import present_pack_result_dialog

_SCAN_PROFILES: list[ScanProfile] = [
    ScanProfile.QUICK,
    ScanProfile.FULL,
    ScanProfile.SUITE,
    ScanProfile.INTEGRITY,
    ScanProfile.CUSTOM,
]
_PROFILE_LABELS = {
    ScanProfile.QUICK: "Quick",
    ScanProfile.FULL: "Full",
    ScanProfile.SUITE: "Suite (malware + rootkits + hardening audit)",
    ScanProfile.INTEGRITY: "Integrity (rkhunter + chkrootkit + unhide)",
    ScanProfile.CUSTOM: "Custom (choose packs)",
}

_CUSTOM_PACK_CHOICES = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")
_RESULT_PACKS = ("clamav", "maldet", "rkhunter", "chkrootkit", "unhide", "lynis")

_PATH_PRESETS = [
    ("Home", "~"),
    ("Downloads", "~/Downloads"),
    ("Desktop", "~/Desktop"),
    ("Custom", ""),
]

_COLUMN_BREAKPOINT = 720
_POLL_MS = 400


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
            name: PackCardState.IDLE for name in _RESULT_PACKS
        }
        self._pack_findings: dict[str, list[dict[str, Any]]] = {name: [] for name in _RESULT_PACKS}
        self._pack_errors: dict[str, str] = {name: "" for name in _RESULT_PACKS}

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
        self.cancel_btn.connect("clicked", self._on_cancel_scan)
        left.append(self.cancel_btn)

        self.path_controls = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        path_buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        path_buttons.set_homogeneous(False)
        self.browse_folder_btn = make_button("Browse folder…")
        self.browse_folder_btn.connect("clicked", self._on_browse_folder)
        self.browse_file_btn = make_button("Browse file…")
        self.browse_file_btn.connect("clicked", self._on_browse_file)
        self.clear_path_btn = make_button("Clear path")
        self.clear_path_btn.connect("clicked", self._on_clear_path)
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
        profile_labels = [_PROFILE_LABELS[p] for p in _SCAN_PROFILES]
        bind_string_combo_row(profile_row, profile_labels)
        profile_row.connect("notify::selected", self._on_profile_changed)
        options_group.add(profile_row)
        self.profile_row = profile_row

        self.path_row = Adw.ComboRow(title="Scan target")
        bind_string_combo_row(self.path_row, [label for label, _ in _PATH_PRESETS])
        self.path_row.connect("notify::selected", self._on_path_preset_changed)
        options_group.add(self.path_row)

        self.packs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.packs_box.set_visible(False)
        packs_label = make_section_heading("Custom packs")
        self.packs_box.append(packs_label)
        self._pack_checks: dict[str, Gtk.CheckButton] = {}
        for pack_name in _CUSTOM_PACK_CHOICES:
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
            return lambda: self._on_pack_card_activated(pack_name)

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
        self._reset_cards_idle()

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
        self._sync_profile_path_ui()
        self._update_path_label()

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
            for idx, item in enumerate(_SCAN_PROFILES):
                if item.value == profile:
                    self.profile_row.set_selected(idx)
                    break
            self._on_profile_changed()
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
            Gtk.Orientation.VERTICAL if width < _COLUMN_BREAKPOINT else Gtk.Orientation.HORIZONTAL
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
        if idx < 0 or idx >= len(_SCAN_PROFILES):
            return ScanProfile.QUICK
        return _SCAN_PROFILES[idx]

    def _profile_value(self) -> str:
        return str(self._profile().value)

    def _is_integrity(self) -> bool:
        return self._profile() is ScanProfile.INTEGRITY

    def _sync_profile_path_ui(self) -> None:
        integrity = self._is_integrity()
        custom = self._profile() is ScanProfile.CUSTOM
        self.path_row.set_visible(not integrity)
        self.path_controls.set_visible(not integrity)
        self.integrity_note.set_visible(integrity)
        self.packs_box.set_visible(custom)

    def _selected_custom_packs(self) -> list[str]:
        return [name for name, check in self._pack_checks.items() if check.get_active()]

    def _on_profile_changed(self, *_args: object) -> None:
        self._sync_profile_path_ui()
        if not self._is_integrity() and self.path_row.get_selected() != 3:
            self._update_path_label()

    def _on_path_preset_changed(self, *_args: object) -> None:
        idx = self.path_row.get_selected()
        if idx == 3:
            if not self._custom_path:
                self._on_browse_folder()
            self._update_path_label()
        else:
            self._custom_path = None
            self._update_path_label()
        self._update_clear_path_visibility()

    def _resolved_paths(self) -> list[str]:
        if self._is_integrity():
            return [str(Path(p).expanduser()) for p in PROFILE_PATHS[ScanProfile.INTEGRITY]]
        idx = self.path_row.get_selected()
        if idx == 3 and self._custom_path:
            return [str(Path(self._custom_path).expanduser())]
        if 0 <= idx < len(_PATH_PRESETS):
            preset = _PATH_PRESETS[idx][1]
            if preset:
                return [str(Path(preset).expanduser())]
        return [str(Path(p).expanduser()) for p in default_paths_for_profile(self._profile_value())]

    def _update_path_label(self) -> None:
        if self._is_integrity():
            return
        paths = self._resolved_paths()
        profile = self._profile_value()
        default = [str(Path(p).expanduser()) for p in PROFILE_PATHS.get(ScanProfile(profile), [])]
        if paths == default:
            self.path_label.set_text(f"Default paths for {profile}: {', '.join(paths)}")
        else:
            self.path_label.set_text(f"Selected: {', '.join(paths)}")
        self._update_clear_path_visibility()

    def _update_clear_path_visibility(self) -> None:
        show = bool(self._custom_path) or self.path_row.get_selected() == 3
        self.clear_path_btn.set_visible(show and not self._is_integrity())

    def _on_browse_folder(self, *_args: object) -> None:
        dialog = Gtk.FileDialog(title="Choose folder to scan")
        dialog.select_folder(self._window, None, self._on_folder_selected)

    def _on_browse_file(self, *_args: object) -> None:
        dialog = Gtk.FileDialog(title="Choose file to scan")
        dialog.open(self._window, None, self._on_file_selected)

    def _on_folder_selected(self, dialog: Gtk.FileDialog, result: object) -> None:
        try:
            folder = dialog.select_folder_finish(result)
        except GLib.Error:
            return
        if folder is None:
            return
        self._custom_path = folder.get_path()
        self.path_row.set_selected(3)
        self._update_path_label()

    def _on_file_selected(self, dialog: Gtk.FileDialog, result: object) -> None:
        try:
            file = dialog.open_finish(result)
        except GLib.Error:
            return
        if file is None:
            return
        self._custom_path = file.get_path()
        self.path_row.set_selected(3)
        self._update_path_label()

    def _on_clear_path(self, *_args: object) -> None:
        self._custom_path = None
        self.path_row.set_selected(0)
        self._update_path_label()

    def _set_scan_controls_sensitive(self, sensitive: bool) -> None:
        self.profile_row.set_sensitive(sensitive)
        self.path_row.set_sensitive(sensitive)
        self.browse_folder_btn.set_sensitive(sensitive)
        self.browse_file_btn.set_sensitive(sensitive)
        self.clear_path_btn.set_sensitive(sensitive)
        self.scan_btn.set_sensitive(sensitive)
        self.packs_box.set_sensitive(sensitive)
        self.cancel_btn.set_visible(not sensitive and self._scanning)
        self.cancel_btn.set_sensitive(not sensitive and self._scanning)

    def _on_cancel_scan(self, *_args: object) -> None:
        if not self._scanning:
            return
        self.cancel_btn.set_sensitive(False)
        self._set_status("Cancelling…")

        def worker() -> dict[str, Any]:
            return request_job_cancel(self.client)

        def done(result: dict[str, Any]) -> bool:
            msg = str(result.get("message") or "cancel requested")
            self._set_status(msg)
            return False

        def failed(message: str) -> bool:
            self.cancel_btn.set_sensitive(True)
            self._set_status(f"Cancel failed: {message}")
            return False

        run_in_thread(worker, done, failed)

    def _reset_cards_idle(self) -> None:
        for name in _RESULT_PACKS:
            self._set_card_state(name, PackCardState.IDLE)

    def _prepare_cards_for_scan(self, expected: list[str]) -> None:
        for name in _RESULT_PACKS:
            if name in expected:
                self._set_card_state(name, PackCardState.PENDING)
            else:
                self._set_card_state(name, PackCardState.SKIPPED)
            self._pack_findings[name] = []
            self._pack_errors[name] = ""

    def _set_card_state(
        self,
        pack: str,
        state: PackCardState,
        *,
        findings: list[dict[str, Any]] | None = None,
        error: str = "",
    ) -> None:
        self._card_states[pack] = state
        if findings is not None:
            self._pack_findings[pack] = findings
        if error:
            self._pack_errors[pack] = error
        card = self._pack_cards[pack]
        match state:
            case PackCardState.IDLE:
                card.set_values("—", "No scan yet")
            case PackCardState.PENDING:
                card.set_values("Pending", "Waiting…", css_class="warning")
            case PackCardState.RUNNING:
                card.set_values("Running…", "In progress", css_class="warning")
            case PackCardState.SKIPPED:
                card.set_values("Skipped", "Not in this scan")
            case PackCardState.CLEAN:
                card.set_values("Clean", "No threats", css_class="success")
            case PackCardState.THREATS:
                n = len(self._pack_findings.get(pack) or [])
                card.set_values(f"{n} threat(s)", "Open for details", css_class="error")
            case PackCardState.ERROR:
                err = self._pack_errors.get(pack) or "Pack error"
                card.set_values("Error", err, css_class="error")

    def _on_pack_card_activated(self, pack: str) -> None:
        state = self._card_states.get(pack, PackCardState.IDLE)
        if state not in (PackCardState.CLEAN, PackCardState.THREATS, PackCardState.ERROR):
            return
        label = {
            PackCardState.CLEAN: "Clean",
            PackCardState.THREATS: "Threats found",
            PackCardState.ERROR: "Error",
        }[state]
        present_pack_result_dialog(
            self._window,
            pack=pack,
            state=label,
            findings=self._pack_findings.get(pack) or [],
            error=self._pack_errors.get(pack) or "",
            client=self.client,
            on_status=self._on_status,
        )

    def _start_poll(self) -> None:
        self._stop_poll()
        self.progress.set_visible(True)
        self.progress.set_fraction(0.0)

        def tick() -> bool:
            if not self._scanning:
                return False
            try:
                status = request_job_status(self.client)
            except RuntimeError:
                return True
            self._apply_job_status(status)
            return True

        self._poll_id = GLib.timeout_add(_POLL_MS, tick)

    def _stop_poll(self) -> None:
        if self._poll_id:
            GLib.source_remove(self._poll_id)
            self._poll_id = 0

    def _apply_job_status(self, status: dict[str, Any]) -> None:
        if not status.get("active"):
            return
        pack = str(status.get("pack") or "")
        message = str(status.get("message") or "Scanning…")
        percent = float(status.get("percent") or 0)
        self._set_status(message if message else f"Running {pack}")
        self.progress.set_visible(True)
        if percent > 0:
            self.progress.set_fraction(min(1.0, max(0.0, percent / 100.0)))
        else:
            self.progress.pulse()
        if pack and pack in self._pack_cards:
            for name in self._expected_packs:
                if name == pack:
                    self._set_card_state(name, PackCardState.RUNNING)
                elif self._card_states.get(name) == PackCardState.RUNNING:
                    self._set_card_state(name, PackCardState.PENDING)

    def _on_start_scan(self, *_args: object) -> None:
        if self._scanning:
            return
        if not self._is_integrity() and self.path_row.get_selected() == 3 and not self._custom_path:
            self._set_status("Choose a folder or file for Custom target")
            return

        packs: list[str] | None = None
        if self._profile() is ScanProfile.CUSTOM:
            packs = self._selected_custom_packs()
            if not packs:
                self._set_status("Select at least one pack for a custom scan")
                return
            unknown = [p for p in packs if p not in _CUSTOM_PACK_CHOICES]
            if unknown:
                self._set_status(f"Unknown packs: {', '.join(unknown)}")
                return

        profile = self._profile()
        self._expected_packs = expected_packs_for_profile(profile, packs)
        self._scanning = True
        self._last_scan = None
        self._set_scan_controls_sensitive(False)
        self._prepare_cards_for_scan(self._expected_packs)
        self.result_banner.set_revealed(False)
        self._set_status("Starting scan…")
        self._start_poll()

        profile_value = self._profile_value()
        paths = self._resolved_paths()

        def worker() -> dict[str, Any]:
            return self.client.start_scan(
                profile=profile_value,
                paths=paths,
                packs=packs,
                quarantine=False,
            )

        run_in_thread(worker, self._on_scan_done, self._on_scan_failed)

    def _on_scan_done(self, result: dict[str, Any]) -> bool:
        self._scanning = False
        self._stop_poll()
        self._set_scan_controls_sensitive(True)
        scan = result.get("scan", {})
        if not isinstance(scan, dict):
            scan = {}
        self._last_scan = scan
        findings = list(scan.get("findings", [])) if isinstance(scan.get("findings"), list) else []
        errors = (
            list(scan.get("pack_errors", [])) if isinstance(scan.get("pack_errors"), list) else []
        )
        clean = bool(scan.get("clean", len(findings) == 0))
        state = str(scan.get("state") or "")

        for name in _RESULT_PACKS:
            card_state, pack_findings, error = pack_result_summary(
                scan,
                name,
                expected=self._expected_packs,
            )
            self._set_card_state(name, card_state, findings=pack_findings, error=error)

        self.progress.set_visible(True)
        self.progress.set_fraction(1.0)

        if state == "cancelled":
            self.result_banner.set_title("Scan cancelled")
            self.result_banner.set_revealed(True)
            self._set_status("Scan cancelled")
        elif clean and not errors:
            self.result_banner.set_title("Scan complete — no threats found")
            self.result_banner.set_revealed(True)
            self._set_status("Scan complete — clean")
        elif clean and errors:
            self.result_banner.set_title("Scan complete — with pack errors")
            self.result_banner.set_revealed(True)
            self._set_status("Scan complete — with errors")
        else:
            self.result_banner.set_title(f"Scan complete — {len(findings)} finding(s)")
            self.result_banner.set_revealed(True)
            self._set_status(f"Scan complete — {len(findings)} finding(s)")

        if self._on_scan_complete:
            self._on_scan_complete()
        return False

    def _on_scan_failed(self, message: str) -> bool:
        self._scanning = False
        self._stop_poll()
        self._set_scan_controls_sensitive(True)
        self.progress.set_visible(False)
        self.result_banner.set_title(f"Scan failed: {message}")
        self.result_banner.set_revealed(True)
        self._set_status(f"Scan failed: {message}")
        for name in self._expected_packs:
            if self._card_states.get(name) in (
                PackCardState.PENDING,
                PackCardState.RUNNING,
            ):
                self._set_card_state(name, PackCardState.ERROR, error=message)
        return False
