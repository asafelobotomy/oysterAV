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
from oyst_core.runtime.bootstrap import PACK_DESCRIPTIONS, RUNTIME_PACKS
from oysterav.gui.widgets.common import (
    make_button,
    make_status_badge,
    run_in_thread,
    show_command_dialog,
)
from oysterav.gui.widgets.progress_button import run_progress_button

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

    def _runtime_info(self, name: str) -> dict[str, Any] | None:
        packs = self._runtime.get("packs")
        if not isinstance(packs, dict):
            return None
        info = packs.get(name)
        return info if isinstance(info, dict) else None

    def _display_packs(self) -> list[dict[str, Any]]:
        """Doctor packs plus any RUNTIME_PACKS missing from doctor (as optional)."""
        packs = [dict(p) for p in self._packs]
        seen = {str(p.get("name", "")) for p in packs}
        for name in sorted(RUNTIME_PACKS):
            if name in seen:
                continue
            packs.append(
                {
                    "name": name,
                    "installed": False,
                    "tier": PackTier.OPTIONAL.value,
                },
            )
        return packs

    def _populate(self) -> None:
        self._detach_groups()
        display = self._display_packs()

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

        first_tier = True
        for tier in _TIER_ORDER:
            tier_packs = [p for p in display if p.get("tier") == tier.value]
            if not tier_packs:
                continue
            group = Adw.PreferencesGroup(title=tier.value.capitalize())
            if first_tier:
                group.set_description(_GROUP_DESCRIPTION)
                first_tier = False
            for pack in tier_packs:
                group.add(self._pack_row(pack))
            self._groups.append(group)

        self._reattach_groups()

    def _pack_path(self, pack: dict[str, Any], rt: dict[str, Any] | None) -> str:
        if rt is not None:
            path = str(rt.get("path") or "").strip()
            if path:
                return path
        details = pack.get("details")
        if isinstance(details, dict):
            binary = str(details.get("binary") or "").strip()
            if binary:
                return binary
            # Firewall exposes active backend rather than a single binary.
            active = str(details.get("active") or "")
            if active and active != "none":
                for key in ("ufw_path", "firewalld_path", "nft_path", "path"):
                    candidate = str(details.get(key) or "").strip()
                    if candidate:
                        return candidate
                return active
        return ""

    def _pack_subtitle(self, pack: dict[str, Any], rt: dict[str, Any] | None) -> str:
        name = str(pack.get("name", ""))
        description = ""
        if rt is not None:
            description = str(rt.get("description") or "")
        if not description:
            description = PACK_DESCRIPTIONS.get(name, "")

        installed = bool(pack.get("installed"))
        private = False
        if rt is not None:
            installed = bool(rt.get("installed") or installed)
            origin = str(rt.get("origin") or rt.get("source") or "missing")
            private = bool(rt.get("private")) or origin in ("private", "runtime")

        path = self._pack_path(pack, rt)
        version = pack.get("version")
        version_text = f"v{version}" if version else "version unknown"

        if not installed:
            parts = [p for p in (description, "Not installed") if p]
            hint = str(pack.get("install_hint") or "").strip()
            if hint and hint not in parts:
                parts.append(hint)
            return " — ".join(parts) if parts else "Not installed"

        origin_label = "Private" if private else "System"
        meta = [origin_label]
        if path:
            meta.append(path)
        meta.append(version_text)
        meta_text = " · ".join(meta)
        if description:
            return f"{description} — {meta_text}"
        return meta_text

    def _pack_row(self, pack: dict[str, Any]) -> Adw.ActionRow:
        row = Adw.ActionRow()
        name = str(pack.get("name", "?"))
        row.set_title(name)
        rt = self._runtime_info(name) if name in RUNTIME_PACKS else None
        row.set_subtitle(self._pack_subtitle(pack, rt))

        if rt is not None:
            installed = bool(rt.get("installed") or pack.get("installed"))
            origin = str(rt.get("origin") or rt.get("source") or "missing")
            private = bool(rt.get("private")) or origin in ("private", "runtime")
            if installed and private:
                btn = make_button("Remove", destructive=True, row_suffix=True)
                btn.connect("clicked", self._on_remove_clicked, name, btn)
                row.add_suffix(btn)
                return row
            if installed:
                label = make_status_badge("Installed", "success")
                row.add_suffix(label)
                return row
            if self._full_mode:
                install_btn = make_button("Install to runtime", suggested=True, row_suffix=True)
                install_btn.connect("clicked", self._on_runtime_install_clicked, name)
            else:
                install_btn = make_button("Install", suggested=True, row_suffix=True)
                install_btn.connect("clicked", self._on_install_clicked, name)
            row.add_suffix(install_btn)
            return row

        installed = bool(pack.get("installed", False))
        if installed:
            suffix = make_status_badge("Installed", "success")
            row.add_suffix(suffix)
            return row

        install_btn = make_button("Install", suggested=True, row_suffix=True)
        install_btn.connect("clicked", self._on_install_clicked, name)
        row.add_suffix(install_btn)
        return row

    def _on_install_clicked(self, button: Gtk.Button, name: str) -> None:
        self._start_install(button, name, confirm_aur=False)

    def _on_runtime_install_clicked(self, button: Gtk.Button, name: str) -> None:
        idle = button.get_label() or "Install to runtime"
        self._set_status(f"Installing {name}…")

        def worker(report: Callable[[int], None]) -> dict[str, Any]:
            def on_progress(_stage: str, percent: int) -> None:
                report(percent)

            result = self.client.runtime_install(name, on_progress=on_progress)
            return dict(result) if isinstance(result, dict) else {"ok": False}

        def done(result: dict[str, Any]) -> None:
            if result.get("ok"):
                self._set_status(f"{name}: {result.get('message', 'installed')}")
                self._refresh_packs()
                return
            message = str(result.get("message") or "Install failed")
            self._set_status(f"Install {name}: {message}")
            show_command_dialog(
                self._dialog_window(),
                heading=f"Install {name}",
                body=message,
                copy_text=message,
            )

        def fail(msg: str) -> None:
            self._set_status(f"Install failed: {msg}")
            show_command_dialog(
                self._dialog_window(),
                heading=f"Install {name}",
                body=msg,
                copy_text=msg,
            )

        run_progress_button(
            button,
            worker,
            busy_verb="Installing",
            idle_label=idle,
            on_success=done,
            on_error=fail,
        )

    def _on_remove_clicked(self, _widget: Gtk.Button, name: str, button: Gtk.Button) -> None:
        idle = button.get_label() or "Remove"
        self._set_status(f"Removing {name}…")

        def worker(report: Callable[[int], None]) -> dict[str, Any]:
            def on_progress(_stage: str, percent: int) -> None:
                report(percent)

            return self.client.runtime_remove(name, on_progress=on_progress)

        def done(result: dict[str, Any]) -> None:
            self._set_status(str(result.get("message", f"Removed {name}")))
            self._refresh_packs()

        def fail(msg: str) -> None:
            self._set_status(f"Remove failed: {msg}")

        run_progress_button(
            button,
            worker,
            busy_verb="Removing",
            idle_label=idle,
            on_success=done,
            on_error=fail,
        )

    def _start_install(self, button: Gtk.Button, name: str, *, confirm_aur: bool) -> None:
        idle = button.get_label() or "Install"
        self._set_status(f"Installing {name}…")

        def worker(report: Callable[[int], None]) -> dict[str, Any]:
            def on_progress(_stage: str, percent: int) -> None:
                report(percent)

            return self.client.pack_install(
                name,
                confirm_aur=confirm_aur,
                on_progress=on_progress,
            )

        def done(result: dict[str, Any]) -> None:
            mode = result.get("mode", "")
            if mode == "aur_confirm" and not confirm_aur:
                self._confirm_aur_install(button, name, result)
                return
            if result.get("ok"):
                self._set_status(f"{name} installed")
                self._refresh_packs()
                return
            self._show_install_failure(name, result)

        def fail(msg: str) -> None:
            self._set_status(f"Install failed: {msg}")

        run_progress_button(
            button,
            worker,
            busy_verb="Installing",
            idle_label=idle,
            on_success=done,
            on_error=fail,
        )

    def _confirm_aur_install(
        self,
        button: Gtk.Button,
        name: str,
        preview: dict[str, Any],
    ) -> None:
        hint = str(preview.get("install_hint", ""))
        message = str(preview.get("message", f"{name} requires an AUR install"))
        dialog = Adw.MessageDialog(
            transient_for=self._dialog_window(),
            heading=f"Install {name} from AUR?",
            body=f"{message}\n\nThis will run:\n{hint}",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("install", "Install from AUR")
        dialog.set_default_response("install")
        dialog.set_close_response("cancel")

        def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
            if response == "install":
                self._start_install(button, name, confirm_aur=True)

        dialog.connect("response", on_response)
        dialog.present()

    def _show_install_failure(self, name: str, result: dict[str, Any]) -> None:
        mode = result.get("mode", "")
        hint = str(result.get("install_hint", ""))
        message = str(result.get("message", "Install failed"))
        reason = str(result.get("reason", ""))
        if reason == "aur_confirmation_required":
            return
        if mode in ("command", "manual", "aur") and hint:
            show_command_dialog(
                self._dialog_window(),
                heading=f"Install {name}",
                body=f"{message}\n\nRun in a terminal:\n{hint}",
                copy_text=hint,
            )
        else:
            self._set_status(f"Install {name}: {message}")

    def _refresh_packs(self) -> None:
        def load() -> dict[str, Any]:
            return {
                "packs": self.client.doctor(),
                "runtime": self.client.runtime_status(),
            }

        def done(data: dict[str, Any]) -> bool:
            packs_raw = data.get("packs")
            packs = packs_raw if isinstance(packs_raw, list) else []
            runtime_raw = data.get("runtime")
            runtime = runtime_raw if isinstance(runtime_raw, dict) else {}
            self.set_packs(list(packs), runtime=runtime)
            if self._on_changed:
                self._on_changed()
            return False

        run_in_thread(load, done, lambda _m: False)
