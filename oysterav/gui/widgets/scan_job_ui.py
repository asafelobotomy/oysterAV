"""Scan job / card / poll UI helpers for ScanPage."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.rpc_actions import request_job_cancel, request_job_status
from oysterav.gui.scan_helpers import PackCardState, pack_result_summary
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
    packs_box: Gtk.Box
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
    _last_scan: dict[str, Any] | None

    def _set_status(self, text: str) -> None: ...


def set_scan_controls_sensitive(page: _ScanJobHost, sensitive: bool) -> None:
    page.profile_row.set_sensitive(sensitive)
    page.path_row.set_sensitive(sensitive)
    page.browse_folder_btn.set_sensitive(sensitive)
    page.browse_file_btn.set_sensitive(sensitive)
    page.clear_path_btn.set_sensitive(sensitive)
    page.scan_btn.set_sensitive(sensitive)
    page.packs_box.set_sensitive(sensitive)
    page.cancel_btn.set_visible(not sensitive and page._scanning)
    page.cancel_btn.set_sensitive(not sensitive and page._scanning)


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
    for name in RESULT_PACKS:
        set_card_state(page, name, PackCardState.IDLE)


def prepare_cards_for_scan(page: _ScanJobHost, expected: list[str]) -> None:
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
    match state:
        case PackCardState.IDLE:
            card.set_values("No scan yet", "")
        case PackCardState.PENDING:
            card.set_values("Pending", "Waiting…", css_class="warning")
        case PackCardState.RUNNING:
            card.set_values("Running…", "In progress", css_class="warning")
        case PackCardState.SKIPPED:
            card.set_values("Skipped", "Not in this scan")
        case PackCardState.CLEAN:
            card.set_values("Clean", "No threats", css_class="success")
        case PackCardState.THREATS:
            n = len(page._pack_findings.get(pack) or [])
            card.set_values(f"{n} threat(s)", "Open for details", css_class="error")
        case PackCardState.ERROR:
            err = page._pack_errors.get(pack) or "Pack error"
            card.set_values("Error", err, css_class="error")


def on_pack_card_activated(page: _ScanJobHost, pack: str) -> None:
    state = page._card_states.get(pack, PackCardState.IDLE)
    if state not in (PackCardState.CLEAN, PackCardState.THREATS, PackCardState.ERROR):
        return
    label = {
        PackCardState.CLEAN: "Clean",
        PackCardState.THREATS: "Threats found",
        PackCardState.ERROR: "Error",
    }[state]
    present_pack_result_dialog(
        page._window,
        pack=pack,
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
    page._set_status(message if message else f"Running {pack}")
    page.progress.set_visible(True)
    if percent > 0:
        page.progress.set_fraction(min(1.0, max(0.0, percent / 100.0)))
    else:
        page.progress.pulse()
    if pack and pack in page._pack_cards:
        for name in page._expected_packs:
            if name == pack:
                set_card_state(page, name, PackCardState.RUNNING)
            elif page._card_states.get(name) == PackCardState.RUNNING:
                set_card_state(page, name, PackCardState.PENDING)


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
