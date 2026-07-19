"""Pack scan result detail dialog with shared finding presentation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.finding_present import normalize_findings, summarize_findings_badge
from oysterav.gui.widgets.common import apply_status_css, make_button, make_section_heading
from oysterav.gui.widgets.finding_list import (
    build_findings_summary_labels,
    populate_findings_list,
)


def present_pack_result_dialog(
    parent: Gtk.Window | None,
    *,
    pack: str,
    state: str,
    findings: list[dict[str, Any]],
    error: str = "",
    client: Any | None = None,
    on_status: Callable[[str], None] | None = None,
) -> None:
    """Show a modal window with per-pack findings and safe actions."""
    dialog = Adw.Window()
    dialog.set_title(f"{pack} results")
    if parent is not None:
        dialog.set_transient_for(parent)
    dialog.set_modal(True)
    dialog.set_default_size(560, 520)

    header = Adw.HeaderBar()
    close_btn = make_button("Close")
    close_btn.connect("clicked", lambda *_: dialog.close())
    header.pack_end(close_btn)

    body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    body.set_margin_start(16)
    body.set_margin_end(16)
    body.set_margin_top(12)
    body.set_margin_bottom(16)

    findings_norm = normalize_findings(findings)
    show_all = {"value": False}

    summary = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    state_label = Gtk.Label(label=f"State: {state}", xalign=0)
    state_label.add_css_class("heading")
    state_lower = state.lower()
    if "error" in state_lower or "fail" in state_lower:
        apply_status_css(state_label, "error")
    elif "clean" in state_lower or state_lower in ("ok", "success", "passed"):
        apply_status_css(state_label, "success")
    elif "threat" in state_lower or "finding" in state_lower:
        apply_status_css(state_label, "error")
    elif state_lower in ("pending", "running", "skipped", "cancelled"):
        apply_status_css(state_label, "warning")
    summary.append(state_label)
    badge = summarize_findings_badge(findings_norm)
    count_label = Gtk.Label(label=f"Summary: {badge}", xalign=0)
    summary.append(count_label)
    pack_text, sev_text = build_findings_summary_labels(findings_norm)
    if findings_norm:
        summary.append(Gtk.Label(label=f"By pack: {pack_text}", xalign=0))
        summary.append(Gtk.Label(label=f"By severity: {sev_text}", xalign=0))
    if error:
        err_label = Gtk.Label(label=f"Error: {error}", xalign=0)
        err_label.set_wrap(True)
        err_label.add_css_class("error")
        summary.append(err_label)
    body.append(summary)

    if not findings_norm and not error:
        empty = Adw.StatusPage(
            title="No threats detected",
            description=f"{pack} completed without findings.",
        )
        empty.set_icon_name("emblem-ok-symbolic")
        body.append(empty)
    else:
        findings_heading = make_section_heading("Findings")
        body.append(findings_heading)
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)

        def on_need_show_all() -> None:
            show_all["value"] = True
            render()

        def render() -> None:
            populate_findings_list(
                list_box,
                findings_norm,
                window=parent,
                client=client,
                on_status=on_status,
                show_all=show_all["value"],
                on_need_show_all=on_need_show_all,
                on_refresh=render,
            )

        render()
        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(list_box)
        body.append(scroll)

    toolbar = Adw.ToolbarView()
    toolbar.add_top_bar(header)
    toolbar.set_content(body)
    dialog.set_content(toolbar)
    dialog.present()
