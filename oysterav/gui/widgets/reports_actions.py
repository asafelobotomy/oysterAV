"""Reports action helpers — handle-open, delete, export dialogs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.config import data_dir
from oyst_core.finding_status import MALWARE_PACKS, finding_is_open
from oysterav.gui.finding_present import is_resolvable_finding
from oysterav.gui.rpc_actions import (
    request_history_delete,
    request_history_delete_all,
    request_history_export,
    request_history_export_all,
    request_history_get,
    request_history_handle_open,
)
from oysterav.gui.widgets.common import run_in_thread


class _ReportsHost(Protocol):
    client: OystClient
    quarantine_open_btn: Gtk.Button
    resolve_open_btn: Gtk.Button
    export_btn: Gtk.Button
    delete_btn: Gtk.Button
    export_all_btn: Gtk.Button
    delete_all_btn: Gtk.Button
    _window: Gtk.Window | None
    _rows: list[dict[str, Any]]
    _selected_job_id: str | None
    _detail_findings: list[dict[str, Any]]
    _detail_gen: int

    def _set_status(self, text: str) -> None: ...

    def refresh(self) -> None: ...

    def _apply_detail(self, result: dict[str, Any], gen: int) -> bool: ...

    def _apply_error(self, message: str) -> bool: ...


def open_quarantine_count(page: _ReportsHost) -> int:
    return sum(
        1
        for f in page._detail_findings
        if finding_is_open(f)
        and str(f.get("pack") or "") in MALWARE_PACKS
        and str(f.get("path") or "") not in {"", "system"}
    )


def open_resolve_count(page: _ReportsHost) -> int:
    return sum(1 for f in page._detail_findings if finding_is_open(f) and is_resolvable_finding(f))


def update_bulk_buttons(page: _ReportsHost) -> None:
    has_job = bool(page._selected_job_id)
    has_rows = bool(page._rows)
    page.quarantine_open_btn.set_sensitive(has_job and open_quarantine_count(page) > 0)
    page.resolve_open_btn.set_sensitive(has_job and open_resolve_count(page) > 0)
    page.export_btn.set_sensitive(has_job)
    page.delete_btn.set_sensitive(has_job)
    page.export_all_btn.set_sensitive(has_rows)
    page.delete_all_btn.set_sensitive(has_rows)


def reload_selected_detail(page: _ReportsHost) -> None:
    job_id = page._selected_job_id
    if not job_id:
        return
    page._detail_gen += 1
    gen = page._detail_gen
    run_in_thread(
        lambda: request_history_get(page.client, job_id),
        lambda result: page._apply_detail(result, gen),
        page._apply_error,
    )


def confirm_handle_open(
    page: _ReportsHost,
    *,
    quarantine: bool = False,
    resolve: bool = False,
) -> None:
    job_id = page._selected_job_id
    if not job_id:
        return
    q_n = open_quarantine_count(page) if quarantine else 0
    r_n = open_resolve_count(page) if resolve else 0
    if quarantine and q_n == 0:
        return
    if resolve and r_n == 0:
        return
    if quarantine:
        heading = "Quarantine open malware findings?"
        body = (
            f"Quarantine {q_n} open malware finding(s) for this report. "
            "Same per-item gates as row Quarantine."
        )
    else:
        heading = "Resolve open rkhunter findings?"
        body = (
            f"Resolve {r_n} open rkhunter finding(s) via whitelist overlay "
            "in one privileged write (one authentication). "
            "Does not edit sshd_config or delete files."
        )
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading=heading,
        body=body,
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Confirm")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def worker() -> dict[str, Any]:
            return request_history_handle_open(
                page.client,
                job_id,
                quarantine=quarantine,
                resolve=resolve,
            )

        def done(result: dict[str, Any]) -> bool:
            q = int(result.get("quarantined") or 0)
            r = int(result.get("resolved") or 0)
            errs = result.get("errors") or []
            err_n = len(errs) if isinstance(errs, list) else 0
            page._set_status(f"Handled open: quarantined={q} resolved={r} errors={err_n}")
            reload_selected_detail(page)
            page.refresh()
            return False

        def failed(message: str) -> bool:
            page._set_status(f"Handle open failed: {message}")
            return False

        run_in_thread(worker, done, failed)

    dialog.connect("response", on_response)
    dialog.present()


def confirm_delete_selected(page: _ReportsHost) -> None:
    job_id = page._selected_job_id
    if not job_id:
        return
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Delete this report?",
        body=f"Permanently remove scan report {job_id} from history.",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Delete")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def done(result: dict[str, Any]) -> bool:
            if result.get("ok"):
                page._set_status(f"Deleted report {job_id}")
                page._selected_job_id = None
                page.refresh()
            else:
                page._set_status(f"Delete failed: {result.get('error') or 'unknown'}")
            return False

        def on_err(message: str) -> bool:
            page._set_status(f"Delete failed: {message}")
            return False

        run_in_thread(
            lambda: request_history_delete(page.client, job_id),
            done,
            on_err,
        )

    dialog.connect("response", on_response)
    dialog.present()


def confirm_delete_all(page: _ReportsHost) -> None:
    if not page._rows:
        return
    n = len(page._rows)
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading="Delete all reports?",
        body=f"Permanently remove all {n} scan report(s) from history.",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("confirm", "Delete all")
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response != "confirm":
            return

        def done(result: dict[str, Any]) -> bool:
            deleted = int(result.get("deleted") or 0)
            page._set_status(f"Deleted {deleted} report(s)")
            page._selected_job_id = None
            page.refresh()
            return False

        def on_err(message: str) -> bool:
            page._set_status(f"Delete all failed: {message}")
            return False

        run_in_thread(
            lambda: request_history_delete_all(page.client),
            done,
            on_err,
        )

    dialog.connect("response", on_response)
    dialog.present()


def export_selected(page: _ReportsHost) -> None:
    job_id = page._selected_job_id
    if not job_id:
        return
    choose_export_format(
        page,
        heading="Export report format",
        on_format=lambda fmt: save_export_dialog(
            page,
            fmt=fmt,
            initial_name=f"oysterav-report-{job_id[:8]}.{fmt}",
            export_fn=lambda path, f: request_history_export(page.client, job_id, path, fmt=f),
        ),
    )


def export_all(page: _ReportsHost) -> None:
    if not page._rows:
        return
    choose_export_format(
        page,
        heading="Export all reports format",
        on_format=lambda fmt: save_export_dialog(
            page,
            fmt=fmt,
            initial_name=f"oysterav-reports.{fmt}",
            export_fn=lambda path, f: request_history_export_all(page.client, path, fmt=f),
        ),
    )


def choose_export_format(
    page: _ReportsHost,
    *,
    heading: str,
    on_format: Callable[[str], None],
) -> None:
    dialog = Adw.MessageDialog(
        transient_for=page._window,
        heading=heading,
        body="Choose JSON (machine-readable) or Markdown (readable report).",
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("json", "JSON")
    dialog.add_response("md", "Markdown")
    dialog.set_default_response("json")
    dialog.set_close_response("cancel")
    dialog.set_response_appearance("json", Adw.ResponseAppearance.SUGGESTED)

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response in {"json", "md"}:
            on_format(response)

    dialog.connect("response", on_response)
    dialog.present()


def save_export_dialog(
    page: _ReportsHost,
    *,
    fmt: str,
    initial_name: str,
    export_fn: Callable[[str, str], dict[str, Any]],
) -> None:
    exports = data_dir() / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    dialog = Gtk.FileDialog(title="Save export")
    dialog.set_initial_name(initial_name)
    dialog.set_initial_folder(Gio.File.new_for_path(str(exports)))

    def on_saved(_dlg: Gtk.FileDialog, result: object) -> None:
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return
        if gfile is None:
            return
        path = gfile.get_path()
        if not path:
            return
        if not path.lower().endswith(f".{fmt}"):
            path = f"{path}.{fmt}"

        def done(payload: dict[str, Any]) -> bool:
            if payload.get("ok"):
                count = payload.get("count", 1)
                page._set_status(f"Exported {count} report(s) to {payload.get('path')}")
            else:
                page._set_status(f"Export failed: {payload.get('error') or 'unknown'}")
            return False

        def on_err(message: str) -> bool:
            page._set_status(f"Export failed: {message}")
            return False

        run_in_thread(
            lambda: export_fn(path, fmt),
            done,
            on_err,
        )

    dialog.save(page._window, None, on_saved)
