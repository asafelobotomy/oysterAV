"""GTK helpers to render grouped scan findings with safe actions."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk  # noqa: E402

from oyst_core.packs.rkhunter_resolve import OVERLAY_PATH
from oysterav.gui.finding_present import (
    DisplayFinding,
    apply_finding_cap,
    collapse_findings,
    finding_display_quarantined,
    finding_display_resolved,
    format_pack_breakdown,
    format_severity_breakdown,
    group_by_pack,
    is_propupd_advisory,
    is_quarantinable_path,
    is_resolvable_finding,
    normalize_findings,
    pack_counts,
    path_exists_for_copy,
    severity_counts,
)
from oysterav.gui.widgets.common import (
    clear_list_box,
    make_button,
    make_section_heading,
    make_status_badge,
    severity_css_class,
)
from oysterav.gui.widgets.finding_actions_ui import (
    action_button,
    confirm_propupd,
    confirm_quarantine,
    confirm_resolve,
    copy_text,
    disabled_label_button,
)

_REVIEW_MANUAL_PACKS = frozenset({"chkrootkit", "unhide", "lynis", "rkhunter"})


def build_findings_summary_labels(findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Return (pack breakdown, severity breakdown) for summary strip."""
    return (
        format_pack_breakdown(pack_counts(findings)),
        format_severity_breakdown(severity_counts(findings)),
    )


def populate_findings_list(
    list_box: Gtk.ListBox,
    findings_raw: object,
    *,
    window: Gtk.Window | None,
    client: Any | None = None,
    on_status: Callable[[str], None] | None = None,
    show_all: bool = False,
    on_need_show_all: Callable[[], None] | None = None,
    job_id: str | None = None,
    on_refresh: Callable[[], None] | None = None,
) -> int:
    """Populate *list_box* with grouped findings. Returns total display row count before cap."""
    clear_list_box(list_box)
    findings = normalize_findings(findings_raw)
    vault_paths = _vault_original_paths(client)
    overlay_text = _overlay_text()
    collapsed = collapse_findings(findings)
    visible, hidden = apply_finding_cap(collapsed, show_all=show_all)
    grouped = group_by_pack(visible)

    for pack, rows in grouped:
        header = Gtk.ListBoxRow()
        header.set_activatable(False)
        header.set_selectable(False)
        hlabel = make_section_heading(f"{pack} ({len(rows)})")
        hlabel.set_margin_start(8)
        hlabel.set_margin_top(10)
        hlabel.set_margin_bottom(4)
        header.set_child(hlabel)
        list_box.append(header)

        for row in rows:
            list_box.append(
                _finding_row(
                    row,
                    window=window,
                    client=client,
                    on_status=on_status,
                    job_id=job_id,
                    on_refresh=on_refresh,
                    vault_paths=vault_paths,
                    overlay_text=overlay_text,
                )
            )

    if hidden > 0 and on_need_show_all is not None:
        more = Gtk.ListBoxRow()
        more.set_activatable(True)
        btn = make_button(f"Show all ({hidden} more)")
        btn.set_halign(Gtk.Align.START)
        btn.set_margin_start(8)
        btn.set_margin_top(8)
        btn.set_margin_bottom(8)
        btn.connect("clicked", lambda *_: on_need_show_all())
        more.set_child(btn)
        list_box.append(more)

    return len(collapsed)


def _vault_original_paths(client: Any | None) -> set[str]:
    if client is None:
        return set()
    try:
        entries = client.quarantine_list()
    except Exception:
        return set()
    paths: set[str] = set()
    if not isinstance(entries, list):
        return paths
    for entry in entries:
        if isinstance(entry, dict):
            path = entry.get("original_path") or entry.get("path")
        else:
            path = getattr(entry, "original_path", None)
        if path:
            paths.add(str(path))
    return paths


def _overlay_text() -> str:
    try:
        if OVERLAY_PATH.is_file():
            return OVERLAY_PATH.read_text(encoding="utf-8")
    except OSError:
        pass
    return ""


def _finding_row(
    row: DisplayFinding,
    *,
    window: Gtk.Window | None,
    client: Any | None,
    on_status: Callable[[str], None] | None,
    job_id: str | None,
    on_refresh: Callable[[], None] | None,
    vault_paths: set[str],
    overlay_text: str,
) -> Gtk.ListBoxRow:
    frow = Gtk.ListBoxRow()
    frow.set_activatable(False)
    outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    outer.set_margin_start(8)
    outer.set_margin_end(8)
    outer.set_margin_top(6)
    outer.set_margin_bottom(6)

    title_text = row.message
    if row.count > 1:
        title_text = f"{row.message}  (×{row.count})"
    title = Gtk.Label(label=title_text, xalign=0)
    title.add_css_class("heading")
    title.set_wrap(True)
    title.set_selectable(True)
    outer.append(title)

    sub_parts: list[str] = []
    if row.path and row.path != "system":
        sub_parts.append(row.path)
    if row.threat_name:
        sub_parts.append(row.threat_name)
    if row.severity:
        sub_parts.append(row.severity)
    subtitle = Gtk.Label(label=" · ".join(sub_parts) if sub_parts else row.pack, xalign=0)
    subtitle.add_css_class("dim-label")
    subtitle.set_wrap(True)
    subtitle.set_selectable(True)
    outer.append(subtitle)

    sev = make_status_badge(row.severity.upper(), severity_css_class(row.severity))
    sev.set_halign(Gtk.Align.START)
    outer.append(sev)

    actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    msg = row.message
    path = row.path
    pack = row.pack

    def on_copy_message() -> None:
        copy_text(msg, on_status)

    actions.append(action_button("Copy message", on_copy_message))
    if path_exists_for_copy(path):

        def on_copy_path() -> None:
            copy_text(path, on_status)

        actions.append(action_button("Copy path", on_copy_path))

    quarantined = finding_display_quarantined(row, vault_paths=vault_paths)
    resolved = finding_display_resolved(row, overlay_text=overlay_text)

    if quarantined:
        actions.append(disabled_label_button("Quarantined"))
    elif client is not None and is_quarantinable_path(path, pack):

        def on_quarantine() -> None:
            confirm_quarantine(window, client, row, on_status, job_id=job_id, on_refresh=on_refresh)

        actions.append(action_button("Quarantine", on_quarantine))

    if client is not None and is_propupd_advisory(row):

        def on_propupd() -> None:
            confirm_propupd(window, client, on_status)

        actions.append(action_button("Refresh baseline", on_propupd))

    if resolved:
        actions.append(disabled_label_button("Resolved"))
    elif client is not None and is_resolvable_finding(row):

        def on_resolve() -> None:
            confirm_resolve(window, client, row, on_status, job_id=job_id, on_refresh=on_refresh)

        actions.append(action_button("Resolve", on_resolve))
    elif pack in _REVIEW_MANUAL_PACKS and not quarantined and not is_quarantinable_path(path, pack):
        if not is_propupd_advisory(row) and not is_resolvable_finding(row):
            hint = Gtk.Label(label="Review manually", xalign=0)
            hint.add_css_class("dim-label")
            actions.append(hint)

    outer.append(actions)

    frow.set_child(outer)
    return frow
