"""Shared security pack list UI for Settings and Setup wizard."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.models import PackTier
from oyst_core.runtime.bootstrap import RUNTIME_PACKS
from oysterav.gui.widgets.bulk_checklist import add_switch_item, make_bulk_expander
from oysterav.gui.widgets.common import make_button, make_status_badge
from oysterav.gui.widgets.packs_display import (
    display_packs,
    pack_subtitle,
    runtime_info,
)
from oysterav.gui.widgets.packs_install_all import (
    missing_pack_names,
    on_install_all_clicked,
)
from oysterav.gui.widgets.packs_install_ui import (
    on_install_clicked,
    on_remove_clicked,
    on_runtime_install_clicked,
)

_TIER_ORDER = (PackTier.REQUIRED, PackTier.RECOMMENDED, PackTier.OPTIONAL)
_GROUP_DESCRIPTION = (
    "Tools from the system PATH or a private runtime copy. "
    "Remove only deletes a private copy (not system packages)."
)


class PackListWidget:
    """Tier-grouped pack list with install / remove / installed suffixes."""

    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window | None = None,
        dialog_parent: Gtk.Window | None = None,
        on_status: Callable[[str], None] | None = None,
        on_changed: Callable[[], None] | None = None,
        full_mode: bool = False,
    ) -> None:
        self.client = client
        self._window = window
        self._dialog_parent = dialog_parent or window
        self._on_status = on_status
        self._on_changed = on_changed
        self._packs: list[dict[str, Any]] = []
        self._runtime: dict[str, Any] = {}
        self._full_mode = full_mode
        self._groups: list[Adw.PreferencesGroup] = []
        self._page: Adw.PreferencesPage | None = None
        self._host_box: Gtk.Box | None = None
        self.install_all_btn = make_button("Install All", suggested=True, row_suffix=True)
        self.install_all_btn.connect("clicked", lambda *a: on_install_all_clicked(self, *a))
        self.install_all_switches: dict[str, Adw.SwitchRow] = {}

        self.container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)

    def as_container(self) -> Gtk.Box:
        """Vertical box hosting tier groups (setup wizard)."""
        self._host_box = self.container
        self._page = None
        self._reattach_groups()
        return self.container

    def attach_to_page(self, page: Adw.PreferencesPage) -> None:
        """Attach tier groups to a preferences page (Settings)."""
        self._page = page
        self._host_box = None
        self._reattach_groups()

    def set_window(self, window: Gtk.Window) -> None:
        self._window = window
        if self._dialog_parent is None:
            self._dialog_parent = window

    def set_dialog_parent(self, parent: Gtk.Window | None) -> None:
        self._dialog_parent = parent or self._window

    def set_packs(
        self,
        packs: list[dict[str, Any]],
        *,
        runtime: dict[str, Any] | None = None,
    ) -> None:
        self._packs = list(packs)
        if runtime is not None:
            self._runtime = dict(runtime)
            mode = str(runtime.get("mode") or "")
            if mode:
                self._full_mode = mode == "full"
        self._populate()

    def get_packs(self) -> list[dict[str, Any]]:
        return list(self._packs)

    def _dialog_window(self) -> Gtk.Window | None:
        return self._dialog_parent or self._window

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _detach_groups(self) -> None:
        for group in self._groups:
            parent = group.get_parent()
            if parent is None:
                continue
            if self._page is not None and parent == self._page:
                self._page.remove(group)
            elif isinstance(parent, Gtk.Box):
                parent.remove(group)
        self._groups.clear()

    def _reattach_groups(self) -> None:
        for group in self._groups:
            parent = group.get_parent()
            if parent is not None:
                continue
            if self._page is not None:
                self._page.add(group)
            elif self._host_box is not None:
                self._host_box.append(group)

    def _populate(self) -> None:
        self._detach_groups()
        self.install_all_switches = {}
        display = display_packs(self._packs)

        if self._runtime and str(self._runtime.get("mode") or "") not in ("", "full"):
            note_group = Adw.PreferencesGroup(title="Private runtime")
            note = Adw.ActionRow(title="Private runtime installs require full mode")
            note.set_subtitle(
                "System packages still count as installed. "
                "Set runtime.mode=full to install missing packs into the private runtime.",
            )
            note.set_sensitive(False)
            note_group.add(note)
            self._groups.append(note_group)

        missing = missing_pack_names(display)
        bulk = Adw.PreferencesGroup(title="Install")
        bulk.set_description(_GROUP_DESCRIPTION)
        install_row = Adw.ActionRow(title="Install All")
        install_row.set_subtitle(
            "Install missing packs (required first, then recommended, then optional)",
        )
        install_row.add_suffix(self.install_all_btn)
        self.install_all_btn.set_sensitive(bool(missing))
        bulk.add(install_row)
        expander = make_bulk_expander(
            "Packs to install",
            subtitle="Toggle which missing packs Install All includes",
            expanded=bool(missing),
        )
        by_name = {str(p.get("name") or ""): p for p in display}
        for name in missing:
            pack = by_name.get(name) or {"name": name}
            switch = add_switch_item(
                expander,
                title=name,
                subtitle=str(pack.get("tier") or ""),
                active=True,
            )
            self.install_all_switches[name] = switch
        if not missing:
            empty = Adw.ActionRow(title="All listed packs are installed")
            empty.set_sensitive(False)
            expander.add_row(empty)
            expander.set_expanded(False)
        bulk.add(expander)
        self._groups.append(bulk)

        for tier in _TIER_ORDER:
            tier_packs = [p for p in display if p.get("tier") == tier.value]
            if not tier_packs:
                continue
            group = Adw.PreferencesGroup(title=tier.value.capitalize())
            for pack in tier_packs:
                group.add(self._pack_row(pack))
            self._groups.append(group)

        self._reattach_groups()

    def _pack_row(self, pack: dict[str, Any]) -> Adw.ActionRow:
        row = Adw.ActionRow()
        name = str(pack.get("name", "?"))
        row.set_title(name)
        rt = runtime_info(self._runtime, name) if name in RUNTIME_PACKS else None
        row.set_subtitle(pack_subtitle(pack, rt))

        if rt is not None:
            installed = bool(rt.get("installed") or pack.get("installed"))
            origin = str(rt.get("origin") or rt.get("source") or "missing")
            private = bool(rt.get("private")) or origin in ("private", "runtime")
            if installed and private:
                btn = make_button("Remove", destructive=True, row_suffix=True)
                btn.connect("clicked", lambda b: on_remove_clicked(self, b, name, btn))
                row.add_suffix(btn)
                return row
            if installed:
                label = make_status_badge("Installed", "success")
                row.add_suffix(label)
                return row
            if self._full_mode:
                install_btn = make_button("Install to runtime", suggested=True, row_suffix=True)
                install_btn.connect(
                    "clicked",
                    lambda b: on_runtime_install_clicked(self, b, name),
                )
            else:
                install_btn = make_button("Install", suggested=True, row_suffix=True)
                install_btn.connect("clicked", lambda b: on_install_clicked(self, b, name))
            row.add_suffix(install_btn)
            return row

        installed = bool(pack.get("installed", False))
        if installed:
            suffix = make_status_badge("Installed", "success")
            row.add_suffix(suffix)
            return row

        install_btn = make_button("Install", suggested=True, row_suffix=True)
        install_btn.connect("clicked", lambda b: on_install_clicked(self, b, name))
        row.add_suffix(install_btn)
        return row
