"""Scan path / profile UI helpers for ScanPage."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.models import PROFILE_PATHS, ScanProfile
from oysterav.gui.widgets import scan_job_ui
from oysterav.gui.widgets.common import default_paths_for_profile
from oysterav.gui.widgets.scan_const import PATH_PRESETS


class _ScanPathHost(Protocol):
    path_row: Adw.ComboRow
    path_controls: Gtk.Box
    integrity_note: Gtk.Label
    path_label: Gtk.Label
    clear_path_btn: Gtk.Button
    _custom_path: str | None
    _window: Gtk.Window | None
    _pack_checks: dict[str, Gtk.CheckButton]

    def _profile(self) -> ScanProfile: ...

    def _profile_value(self) -> str: ...

    def _is_integrity(self) -> bool: ...


def sync_profile_path_ui(page: _ScanPathHost) -> None:
    integrity = page._is_integrity()
    page.path_row.set_visible(not integrity)
    page.path_controls.set_visible(not integrity)
    page.integrity_note.set_visible(integrity)
    scan_job_ui.sync_custom_pack_select_ui(page)  # type: ignore[arg-type]


def selected_custom_packs(page: _ScanPathHost) -> list[str]:
    return [name for name, check in page._pack_checks.items() if check.get_active()]


def on_profile_changed(page: _ScanPathHost, *_args: object) -> None:
    sync_profile_path_ui(page)
    if not page._is_integrity() and page.path_row.get_selected() != 3:
        update_path_label(page)
    scan_job_ui.sync_result_cards_for_profile(page)  # type: ignore[arg-type]


def on_path_preset_changed(page: _ScanPathHost, *_args: object) -> None:
    idx = page.path_row.get_selected()
    if idx == 3:
        if not page._custom_path:
            on_browse_folder(page)
        update_path_label(page)
    else:
        page._custom_path = None
        update_path_label(page)
    update_clear_path_visibility(page)


def resolved_paths(page: _ScanPathHost) -> list[str]:
    if page._is_integrity():
        return [str(Path(p).expanduser()) for p in PROFILE_PATHS[ScanProfile.INTEGRITY]]
    idx = page.path_row.get_selected()
    if idx == 3 and page._custom_path:
        return [str(Path(page._custom_path).expanduser())]
    if 0 <= idx < len(PATH_PRESETS):
        preset = PATH_PRESETS[idx][1]
        if preset:
            return [str(Path(preset).expanduser())]
    return [str(Path(p).expanduser()) for p in default_paths_for_profile(page._profile_value())]


def update_path_label(page: _ScanPathHost) -> None:
    if page._is_integrity():
        return
    paths = resolved_paths(page)
    profile = page._profile_value()
    default = [str(Path(p).expanduser()) for p in PROFILE_PATHS.get(ScanProfile(profile), [])]
    if paths == default:
        page.path_label.set_text(f"Default paths for {profile}: {', '.join(paths)}")
    else:
        page.path_label.set_text(f"Selected: {', '.join(paths)}")
    update_clear_path_visibility(page)


def update_clear_path_visibility(page: _ScanPathHost) -> None:
    show = bool(page._custom_path) or page.path_row.get_selected() == 3
    page.clear_path_btn.set_visible(show and not page._is_integrity())


def on_browse_folder(page: _ScanPathHost, *_args: object) -> None:
    dialog = Gtk.FileDialog(title="Choose folder to scan")
    dialog.select_folder(page._window, None, lambda d, r: on_folder_selected(page, d, r))


def on_browse_file(page: _ScanPathHost, *_args: object) -> None:
    dialog = Gtk.FileDialog(title="Choose file to scan")
    dialog.open(page._window, None, lambda d, r: on_file_selected(page, d, r))


def on_folder_selected(page: _ScanPathHost, dialog: Gtk.FileDialog, result: object) -> None:
    try:
        folder = dialog.select_folder_finish(result)
    except GLib.Error:
        return
    if folder is None:
        return
    page._custom_path = folder.get_path()
    page.path_row.set_selected(3)
    update_path_label(page)


def on_file_selected(page: _ScanPathHost, dialog: Gtk.FileDialog, result: object) -> None:
    try:
        file = dialog.open_finish(result)
    except GLib.Error:
        return
    if file is None:
        return
    page._custom_path = file.get_path()
    page.path_row.set_selected(3)
    update_path_label(page)


def on_clear_path(page: _ScanPathHost, *_args: object) -> None:
    page._custom_path = None
    page.path_row.set_selected(0)
    update_path_label(page)
