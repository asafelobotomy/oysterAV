"""Reports tab — scan history master–detail (Search & Destroy–inspired)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.finding_present import normalize_findings, summarize_findings_badge
from oysterav.gui.rpc_actions import request_history_get, request_history_list
from oysterav.gui.widgets import reports_actions, reports_format
from oysterav.gui.widgets.common import (
    clear_list_box,
    format_relative_time,
    make_button,
    make_section_heading,
    make_status_badge,
    run_in_thread,
)
from oysterav.gui.widgets.finding_list import (
    build_findings_summary_labels,
    populate_findings_list,
)


class ReportsPage:
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
        self._rows: list[dict[str, Any]] = []
        self._row_ids: dict[Gtk.ListBoxRow, str] = {}
        self._selected_job_id: str | None = None
        self._pending_job_id: str | None = None
        self._list_gen = 0
        self._detail_gen = 0
        self._detail_findings: list[dict[str, Any]] = []
        self._findings_show_all = False

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root.set_margin_start(12)
        root.set_margin_end(12)
        root.set_margin_top(12)
        root.set_margin_bottom(12)

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.refresh_btn = make_button("Refresh")
        self.refresh_btn.connect("clicked", lambda *_: self.refresh())
        toolbar.append(self.refresh_btn)
        self.quarantine_open_btn = make_button("Quarantine open")
        self.quarantine_open_btn.set_sensitive(False)
        self.quarantine_open_btn.connect(
            "clicked",
            lambda *_: reports_actions.confirm_handle_open(self, quarantine=True),
        )
        toolbar.append(self.quarantine_open_btn)
        self.resolve_open_btn = make_button("Resolve open")
        self.resolve_open_btn.set_sensitive(False)
        self.resolve_open_btn.connect(
            "clicked",
            lambda *_: reports_actions.confirm_handle_open(self, resolve=True),
        )
        toolbar.append(self.resolve_open_btn)
        toolbar.append(Gtk.Box(hexpand=True))
        self.export_btn = make_button("Export")
        self.export_btn.set_sensitive(False)
        self.export_btn.connect("clicked", lambda *_: reports_actions.export_selected(self))
        toolbar.append(self.export_btn)
        self.export_all_btn = make_button("Export all")
        self.export_all_btn.set_sensitive(False)
        self.export_all_btn.connect("clicked", lambda *_: reports_actions.export_all(self))
        toolbar.append(self.export_all_btn)
        self.delete_btn = make_button("Delete", destructive=True)
        self.delete_btn.set_sensitive(False)
        self.delete_btn.connect("clicked", lambda *_: reports_actions.confirm_delete_selected(self))
        toolbar.append(self.delete_btn)
        self.delete_all_btn = make_button("Delete all", destructive=True)
        self.delete_all_btn.set_sensitive(False)
        self.delete_all_btn.connect("clicked", lambda *_: reports_actions.confirm_delete_all(self))
        toolbar.append(self.delete_all_btn)
        root.append(toolbar)

        self.paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.paned.set_hexpand(True)
        self.paned.set_vexpand(True)
        self.paned.set_position(300)

        list_scroll = Gtk.ScrolledWindow()
        list_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        list_scroll.set_hexpand(True)
        list_scroll.set_vexpand(True)
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.list_box.connect("row-selected", self._on_row_selected)
        list_scroll.set_child(self.list_box)
        self.paned.set_start_child(list_scroll)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        self.detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.detail_box.set_margin_start(16)
        self.detail_box.set_margin_end(16)
        self.detail_box.set_margin_top(8)
        self.detail_box.set_margin_bottom(8)

        self.empty_page = Adw.StatusPage(
            title="No scan reports yet",
            description="Run a scan from the Scan tab to generate your first report.",
        )
        self.empty_page.set_icon_name("document-open-recent-symbolic")
        self.detail_box.append(self.empty_page)

        self.select_page = Adw.StatusPage(
            title="Select a report",
            description="Choose a scan report from the list to view detailed results.",
        )
        self.select_page.set_icon_name("view-list-symbolic")
        self.select_page.set_visible(False)
        self.detail_box.append(self.select_page)

        self.detail_group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.detail_group.set_visible(False)
        self._detail_labels: dict[str, Gtk.Label] = {}
        for key, title in (
            ("profile", "Scan type"),
            ("started", "Started"),
            ("finished", "Finished"),
            ("duration", "Duration"),
            ("state", "State"),
            ("paths", "Paths"),
            ("by_pack", "By pack"),
            ("by_severity", "By severity"),
            ("summary", "Summary"),
        ):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            heading = make_section_heading(title)
            value = Gtk.Label(label="—", xalign=0)
            value.set_wrap(True)
            value.set_selectable(True)
            box.append(heading)
            box.append(value)
            self._detail_labels[key] = value
            self.detail_group.append(box)

        findings_heading = make_section_heading("Findings")
        self.detail_group.append(findings_heading)
        self.findings_empty = Gtk.Label(label="No threats detected", xalign=0)
        self.findings_empty.add_css_class("dim-label")
        self.detail_group.append(self.findings_empty)
        self.findings_list = Gtk.ListBox()
        self.findings_list.set_selection_mode(Gtk.SelectionMode.NONE)
        self.findings_list.set_visible(False)
        self.detail_group.append(self.findings_list)

        errors_heading = make_section_heading("Errors")
        self._errors_heading = errors_heading
        self.detail_group.append(errors_heading)
        self.errors_label = Gtk.Label(label="", xalign=0)
        self.errors_label.add_css_class("error")
        self.errors_label.set_wrap(True)
        self.errors_label.set_selectable(True)
        self.detail_group.append(self.errors_label)

        self.detail_box.append(self.detail_group)
        detail_scroll.set_child(self.detail_box)
        self.paned.set_end_child(detail_scroll)
        root.append(self.paned)

        self.widget = root

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def refresh(self) -> None:
        self._list_gen += 1
        gen = self._list_gen
        run_in_thread(
            lambda: request_history_list(self.client, limit=50),
            lambda rows: self._apply_list(rows, gen),
            self._apply_error,
        )

    def focus_job(self, job_id: str) -> None:
        """Select *job_id* after the next list load (Dashboard deep-link)."""
        self._pending_job_id = job_id
        self.refresh()

    def _apply_list(self, rows: list[dict[str, Any]], gen: int) -> bool:
        if gen != self._list_gen:
            return False
        self._rows = rows if isinstance(rows, list) else []
        self._row_ids.clear()
        clear_list_box(self.list_box)
        self._selected_job_id = None
        self._show_idle_detail(has_rows=bool(self._rows))

        if not self._rows:
            return False

        for item in self._rows:
            job_id = str(item.get("job_id") or "")
            if not job_id:
                continue
            row = Gtk.ListBoxRow()
            self._row_ids[row] = job_id
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            box.set_margin_start(12)
            box.set_margin_end(12)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            profile = str(item.get("profile") or "?").capitalize()
            title = Gtk.Label(label=f"{profile} scan", xalign=0)
            title.add_css_class("heading")
            when = format_relative_time(item.get("started_at"))
            badge_text, badge_class = reports_format.status_label(item)
            subtitle = Gtk.Label(label=when, xalign=0)
            subtitle.add_css_class("dim-label")
            badge = make_status_badge(badge_text, badge_class)
            header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            title_box.set_hexpand(True)
            title_box.append(title)
            title_box.append(subtitle)
            header.append(title_box)
            header.append(badge)
            box.append(header)
            row.set_child(box)
            self.list_box.append(row)

        if self._pending_job_id:
            self._select_pending()
        return False

    def _select_pending(self) -> None:
        job_id = self._pending_job_id
        self._pending_job_id = None
        if not job_id:
            return
        for row, rid in self._row_ids.items():
            if rid == job_id:
                self.list_box.select_row(row)
                return
        self._set_status(f"Report not found: {job_id}")

    def _show_idle_detail(self, *, has_rows: bool) -> None:
        self.detail_group.set_visible(False)
        self.quarantine_open_btn.set_sensitive(False)
        self.resolve_open_btn.set_sensitive(False)
        self.export_btn.set_sensitive(False)
        self.delete_btn.set_sensitive(False)
        self.export_all_btn.set_sensitive(has_rows)
        self.delete_all_btn.set_sensitive(has_rows)
        if has_rows:
            self.empty_page.set_visible(False)
            self.select_page.set_visible(True)
        else:
            self.select_page.set_visible(False)
            self.empty_page.set_visible(True)

    def _apply_error(self, message: str) -> bool:
        self._set_status(f"Reports error: {message}")
        return False

    def _on_row_selected(self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            self._selected_job_id = None
            self._show_idle_detail(has_rows=bool(self._rows))
            return
        job_id = self._row_ids.get(row)
        if not job_id:
            return
        self._selected_job_id = job_id
        self._detail_gen += 1
        self._findings_show_all = False
        gen = self._detail_gen
        run_in_thread(
            lambda: request_history_get(self.client, job_id),
            lambda result: self._apply_detail(result, gen),
            self._apply_error,
        )

    def _render_findings(self) -> None:
        findings = self._detail_findings
        reports_actions.update_bulk_buttons(self)
        if not findings:
            self.findings_list.set_visible(False)
            self.findings_empty.set_visible(True)
            return
        self.findings_empty.set_visible(False)
        self.findings_list.set_visible(True)
        populate_findings_list(
            self.findings_list,
            findings,
            window=self._window,
            client=self.client,
            on_status=self._set_status,
            show_all=self._findings_show_all,
            on_need_show_all=self._on_show_all_findings,
            job_id=self._selected_job_id,
            on_refresh=lambda: reports_actions.reload_selected_detail(self),
        )

    def _on_show_all_findings(self) -> None:
        self._findings_show_all = True
        self._render_findings()

    def _apply_detail(self, result: dict[str, Any], gen: int) -> bool:
        if gen != self._detail_gen:
            return False
        if not isinstance(result, dict) or not result:
            self._set_status("Report detail unavailable")
            return False

        self.empty_page.set_visible(False)
        self.select_page.set_visible(False)
        self.detail_group.set_visible(True)

        profile = str(result.get("profile") or "?").capitalize()
        self._detail_labels["profile"].set_text(f"{profile} scan")
        self._detail_labels["started"].set_text(
            reports_format.format_timestamp(result.get("started_at"))
        )
        self._detail_labels["finished"].set_text(
            reports_format.format_timestamp(result.get("finished_at"))
        )
        self._detail_labels["duration"].set_text(
            reports_format.format_duration(result.get("started_at"), result.get("finished_at"))
        )
        state = str(result.get("state") or "completed")
        findings = normalize_findings(result.get("findings"))
        self._detail_findings = findings
        raw_errors = result.get("pack_errors")
        pack_errors: list[Any] = raw_errors if isinstance(raw_errors, list) else []
        badge = summarize_findings_badge(findings)
        clean = bool(result.get("clean", True))
        if state == "cancelled":
            state_text = "Cancelled"
        elif pack_errors and clean and not findings:
            state_text = "Completed with errors"
        elif findings and clean:
            state_text = f"Completed — {badge}"
        elif not clean:
            state_text = badge
        else:
            state_text = "Completed — clean"
        self._detail_labels["state"].set_text(state_text)

        raw_paths = result.get("paths")
        paths: list[Any] = raw_paths if isinstance(raw_paths, list) else []
        self._detail_labels["paths"].set_text(", ".join(str(p) for p in paths) if paths else "—")
        pack_text, sev_text = build_findings_summary_labels(findings)
        self._detail_labels["by_pack"].set_text(pack_text)
        self._detail_labels["by_severity"].set_text(sev_text)
        self._detail_labels["summary"].set_text(badge if findings else "Clean")

        self._render_findings()

        if pack_errors:
            self._errors_heading.set_visible(True)
            self.errors_label.set_visible(True)
            lines = []
            for err in pack_errors:
                if isinstance(err, dict):
                    pack = str(err.get("pack") or "?")
                    msg = str(err.get("error") or "")
                    lines.append(f"{pack}: {msg}" if msg else pack)
                else:
                    lines.append(str(err))
            self.errors_label.set_text("\n".join(lines))
        else:
            self._errors_heading.set_visible(False)
            self.errors_label.set_visible(False)
            self.errors_label.set_text("")
        return False
