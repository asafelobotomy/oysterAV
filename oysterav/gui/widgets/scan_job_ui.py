"""Scan job / card / poll UI helpers for ScanPage."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import ScanProfile
from oysterav.gui.rpc_actions import request_job_cancel, request_job_status
from oysterav.gui.scan_helpers import (
    PackCardState,
    advance_pack_card_states,
    expected_packs_for_profile,
    pack_card_progress_fraction,
    pack_card_purpose,
    pack_card_title,
    pack_progress_status_text,
    pack_result_summary,
)
from oysterav.gui.widgets.common import StatusCard, run_in_thread
from oysterav.gui.widgets.scan_const import POLL_MS, RESULT_PACKS
from oysterav.gui.widgets.scan_result_dialog import present_pack_result_dialog


class _ScanJobHost(Protocol):
    client: OystClient
    profile_row: Adw.ComboRow
    path_row: Adw.ComboRow
    browse_folder_btn: Gtk.Button
    browse_file_btn: Gtk.Button
    clear_path_btn: Gtk.Button
    scan_btn: Gtk.Button
    cancel_btn: Gtk.Button
    progress: Gtk.ProgressBar
    result_banner: Adw.Banner
    status_label: Gtk.Label
    _window: Gtk.Window | None
    _on_status: Callable[[str], None] | None
    _on_scan_complete: Callable[[], None] | None
    _scanning: bool
    _poll_id: int
    _expected_packs: list[str]
    _card_states: dict[str, PackCardState]
    _pack_findings: dict[str, list[dict[str, Any]]]
    _pack_errors: dict[str, str]
    _pack_cards: dict[str, StatusCard]
    _pack_checks: dict[str, Gtk.CheckButton]
    _last_scan: dict[str, Any] | None
    _job_percent: float

    def _set_status(self, text: str) -> None: ...

    def _profile(self) -> ScanProfile: ...


def set_scan_controls_sensitive(page: _ScanJobHost, sensitive: bool) -> None:
    page.profile_row.set_sensitive(sensitive)
    page.path_row.set_sensitive(sensitive)
    page.browse_folder_btn.set_sensitive(sensitive)
    page.browse_file_btn.set_sensitive(sensitive)
    page.clear_path_btn.set_sensitive(sensitive)
    page.scan_btn.set_sensitive(sensitive)
    for check in page._pack_checks.values():
        check.set_sensitive(sensitive)
    page.cancel_btn.set_visible(not sensitive and page._scanning)
    page.cancel_btn.set_sensitive(not sensitive and page._scanning)
    sync_custom_pack_select_ui(page)


def sync_custom_pack_select_ui(page: _ScanJobHost) -> None:
    """Show per-card checkboxes only for the Custom scan profile."""
    custom = page._profile() is ScanProfile.CUSTOM
    for name, card in page._pack_cards.items():
        card.set_select_visible(custom)
        check = page._pack_checks.get(name)
        if check is not None:
            check.set_sensitive(custom and not page._scanning)


def on_cancel_scan(page: _ScanJobHost, *_args: object) -> None:
    if not page._scanning:
        return
    page.cancel_btn.set_sensitive(False)
    page._set_status("Cancelling…")

    def worker() -> dict[str, Any]:
        return request_job_cancel(page.client)

    def done(result: dict[str, Any]) -> bool:
        msg = str(result.get("message") or "cancel requested")
        page._set_status(msg)
        return False

    def failed(message: str) -> bool:
        page.cancel_btn.set_sensitive(True)
        page._set_status(f"Cancel failed: {message}")
        return False

    run_in_thread(worker, done, failed)


def reset_cards_idle(page: _ScanJobHost) -> None:
    sync_result_cards_for_profile(page)


def sync_result_cards_for_profile(page: _ScanJobHost) -> None:
    """Grey out packs not used by the selected profile; keep included packs active."""
    if page._scanning:
        return
    custom: list[str] | None = None
    if page._profile() is ScanProfile.CUSTOM:
        custom = [name for name, check in page._pack_checks.items() if check.get_active()]
    expected = expected_packs_for_profile(page._profile(), custom)
    for name in RESULT_PACKS:
        page._pack_findings[name] = []
        page._pack_errors[name] = ""
        if name in expected:
            set_card_state(page, name, PackCardState.IDLE)
        else:
            set_card_state(page, name, PackCardState.EXCLUDED)


def prepare_cards_for_scan(page: _ScanJobHost, expected: list[str]) -> None:
    page._job_percent = 0.0
    for name in RESULT_PACKS:
        if name in expected:
            set_card_state(page, name, PackCardState.PENDING)
        else:
            set_card_state(page, name, PackCardState.SKIPPED)
        page._pack_findings[name] = []
        page._pack_errors[name] = ""


def set_card_state(
    page: _ScanJobHost,
    pack: str,
    state: PackCardState,
    *,
    findings: list[dict[str, Any]] | None = None,
    error: str = "",
) -> None:
    page._card_states[pack] = state
    if findings is not None:
        page._pack_findings[pack] = findings
    if error:
        page._pack_errors[pack] = error
    card = page._pack_cards[pack]
    purpose = pack_card_purpose(pack)
    selecting = page._profile() is ScanProfile.CUSTOM
    # Custom mode: keep cards bright so checkboxes stay easy to toggle.
    active = selecting or state not in (PackCardState.EXCLUDED, PackCardState.SKIPPED)
    match state:
        case PackCardState.IDLE:
            card.set_values("Will run", purpose)
        case PackCardState.EXCLUDED:
            card.set_values("Not used", "Not part of this profile")
        case PackCardState.PENDING:
            card.set_values("Waiting", "Starts after earlier packs", css_class="warning")
        case PackCardState.RUNNING:
            card.set_values("Scanning…", "In progress now", css_class="warning")
        case PackCardState.DONE:
            card.set_values("Done", "Waiting for other packs", css_class="success")
        case PackCardState.SKIPPED:
            card.set_values("Not used", "Not part of this scan")
        case PackCardState.CLEAN:
            card.set_values("Clean", "No threats found", css_class="success")
        case PackCardState.THREATS:
            n = len(page._pack_findings.get(pack) or [])
            label = "1 threat" if n == 1 else f"{n} threats"
            card.set_values(label, "Open for details", css_class="error")
        case PackCardState.ERROR:
            err = page._pack_errors.get(pack) or "Pack error"
            card.set_values("Failed", err, css_class="error")
    card.set_active_appearance(active)
    refresh_card_progress(page, pack)


def refresh_card_progress(page: _ScanJobHost, pack: str) -> None:
    state = page._card_states.get(pack, PackCardState.IDLE)
    if not page._scanning and state in (PackCardState.IDLE, PackCardState.EXCLUDED):
        page._pack_cards[pack].set_progress(None)
        return
    overall = float(getattr(page, "_job_percent", 0.0) or 0.0)
    frac = pack_card_progress_fraction(pack, state, page._expected_packs, overall)
    page._pack_cards[pack].set_progress(frac)


def on_pack_card_activated(page: _ScanJobHost, pack: str) -> None:
    state = page._card_states.get(pack, PackCardState.IDLE)
    if state not in (PackCardState.CLEAN, PackCardState.THREATS, PackCardState.ERROR):
        return
    label = {
        PackCardState.CLEAN: "Clean",
        PackCardState.THREATS: "Threats found",
        PackCardState.ERROR: "Failed",
    }[state]
    present_pack_result_dialog(
        page._window,
        pack=pack_card_title(pack),
        state=label,
        findings=page._pack_findings.get(pack) or [],
        error=page._pack_errors.get(pack) or "",
        client=page.client,
        on_status=page._on_status,
    )


def start_poll(page: _ScanJobHost) -> None:
    stop_poll(page)
    page.progress.set_visible(True)
    page.progress.set_fraction(0.0)

    def tick() -> bool:
        if not page._scanning:
            return False
        try:
            status = request_job_status(page.client)
        except RuntimeError:
            return True
        apply_job_status(page, status)
        return True

    page._poll_id = GLib.timeout_add(POLL_MS, tick)


def stop_poll(page: _ScanJobHost) -> None:
    if page._poll_id:
        GLib.source_remove(page._poll_id)
        page._poll_id = 0


def apply_job_status(page: _ScanJobHost, status: dict[str, Any]) -> None:
    if not status.get("active"):
        return
    pack = str(status.get("pack") or "")
    message = str(status.get("message") or "Scanning…")
    percent = float(status.get("percent") or 0)
    page._job_percent = percent
    progress_text = pack_progress_status_text(
        page._expected_packs,
        pack,
        fallback=message if message else "Scanning…",
    )
    page._set_status(progress_text)
    page.progress.set_visible(True)
    if percent > 0:
        page.progress.set_fraction(min(1.0, max(0.0, percent / 100.0)))
    else:
        page.progress.pulse()
    if pack and pack in page._pack_cards:
        updated = advance_pack_card_states(page._expected_packs, pack, page._card_states)
        for name in page._expected_packs:
            new_state = updated.get(name)
            if new_state is not None and page._card_states.get(name) != new_state:
                set_card_state(page, name, new_state)
    for name in page._expected_packs:
        refresh_card_progress(page, name)


def on_scan_done(page: _ScanJobHost, result: dict[str, Any]) -> bool:
    page._scanning = False
    stop_poll(page)
    set_scan_controls_sensitive(page, True)
    scan = result.get("scan", {})
    if not isinstance(scan, dict):
        scan = {}
    page._last_scan = scan
    findings = list(scan.get("findings", [])) if isinstance(scan.get("findings"), list) else []
    errors = list(scan.get("pack_errors", [])) if isinstance(scan.get("pack_errors"), list) else []
    clean = bool(scan.get("clean", len(findings) == 0))
    state = str(scan.get("state") or "")

    for name in RESULT_PACKS:
        card_state, pack_findings, error = pack_result_summary(
            scan,
            name,
            expected=page._expected_packs,
        )
        set_card_state(page, name, card_state, findings=pack_findings, error=error)

    page.progress.set_visible(True)
    page.progress.set_fraction(1.0)

    if state == "cancelled":
        page.result_banner.set_title("Scan cancelled")
        page.result_banner.set_revealed(True)
        page._set_status("Scan cancelled")
    elif clean and not errors:
        page.result_banner.set_title("Scan complete — no threats found")
        page.result_banner.set_revealed(True)
        page._set_status("Scan complete — clean")
    elif clean and errors:
        page.result_banner.set_title("Scan complete — with pack errors")
        page.result_banner.set_revealed(True)
        page._set_status("Scan complete — with errors")
    else:
        page.result_banner.set_title(f"Scan complete — {len(findings)} finding(s)")
        page.result_banner.set_revealed(True)
        page._set_status(f"Scan complete — {len(findings)} finding(s)")

    if page._on_scan_complete:
        page._on_scan_complete()
    return False


def on_scan_failed(page: _ScanJobHost, message: str) -> bool:
    page._scanning = False
    stop_poll(page)
    set_scan_controls_sensitive(page, True)
    page.progress.set_visible(False)
    page.result_banner.set_title(f"Scan failed: {message}")
    page.result_banner.set_revealed(True)
    page._set_status(f"Scan failed: {message}")
    for name in page._expected_packs:
        if page._card_states.get(name) in (
            PackCardState.PENDING,
            PackCardState.RUNNING,
        ):
            set_card_state(page, name, PackCardState.ERROR, error=message)
    return False
