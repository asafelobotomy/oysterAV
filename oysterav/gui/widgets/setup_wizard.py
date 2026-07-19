"""First-time setup wizard."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oysterav.gui.widgets.common import (
    bind_string_combo_row,
    make_button,
    make_section_heading,
    run_in_thread,
    show_command_dialog,
)
from oysterav.gui.widgets.packs import PackListWidget
from oysterav.gui.widgets.runtime_ui import (
    bootstrap_runtime_from_gui,
    format_runtime_status_line,
)
from oysterav.gui.widgets.schedule_ui import (
    format_timer_status,
    show_schedule_result,
    timer_is_present,
)


PAGE_TITLES = (
    "Welcome",
    "Security packs",
    "Preferences",
    "Scheduling",
    "Ready",
)


def format_check_summary(setup: dict[str, Any], *, running: bool = False) -> str:
    if running:
        return "Running doctor…"
    missing_required = list(setup.get("missing_required") or [])
    missing_recommended = list(setup.get("missing_recommended") or [])
    lines: list[str] = []
    if missing_required:
        lines.append(
            f"Required missing ({len(missing_required)}): {', '.join(missing_required)}",
        )
    else:
        lines.append("All required packs are installed.")
    if missing_recommended:
        lines.append(
            f"Recommended missing ({len(missing_recommended)}): {', '.join(missing_recommended)}",
        )
    elif not missing_required:
        lines.append("All recommended packs are installed.")
    return "\n".join(lines)


def format_ready_checklist(
    setup: dict[str, Any],
    *,
    bootstrap_ran: bool,
    schedule_installed: bool,
    auto_quarantine: bool,
    full_mode: bool,
) -> str:
    """Concise Ready-page summary of what was done vs still optional."""
    missing = list(setup.get("missing_required") or [])
    skipped = "required_packs" in set(setup.get("skipped_steps") or [])
    if missing and skipped:
        packs_line = f"Required packs: skipped ({', '.join(missing)})"
    elif missing:
        packs_line = f"Required packs: still missing ({', '.join(missing)})"
    else:
        packs_line = "Required packs: installed"
    if bootstrap_ran:
        bootstrap_line = "Runtime / signatures: done"
    elif full_mode:
        bootstrap_line = "Runtime / signatures: not run (optional — Settings → Maintenance)"
    else:
        bootstrap_line = "Runtime / signatures: lite mode (host packages)"
    schedule_line = (
        "Scheduled scan: timer installed"
        if schedule_installed
        else "Scheduled scan: not installed (optional — Settings → Scheduling)"
    )
    quarantine_line = f"Auto-quarantine: {'on' if auto_quarantine else 'off'}"
    next_steps = (
        "Next: Scan tab · Settings → Services (helper) · Settings → Maintenance (Update all)"
    )
    return "\n".join(
        [packs_line, bootstrap_line, schedule_line, quarantine_line, "", next_steps],
    )


def schedule_timer_button_label(
    *,
    present: bool,
    profile: str,
    frequency: str,
) -> str:
    action = "Reinstall" if present else "Install"
    return f"{action} {frequency} {profile}-scan timer"


def should_show_wizard(client: OystClient) -> bool:
    try:
        return bool(client.setup_status().get("needs_attention", True))
    except RuntimeError:
        return True


class SetupWizard:
    def __init__(
        self,
        client: OystClient,
        *,
        window: Gtk.Window,
        on_complete: Callable[[], None] | None = None,
        on_changed: Callable[[], None] | None = None,
        on_navigate: Callable[[str], None] | None = None,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self._parent_window = window
        self._on_complete = on_complete
        self._on_changed = on_changed
        self._on_navigate = on_navigate
        self._on_status = on_status
        self._packs: list[dict[str, Any]] = []
        self._setup: dict[str, Any] = {}
        self._dismissed = False
        self._current = 0
        self._doctor_running = False
        self._doctor_done = False
        self._install_skipped = False
        self._full_mode = self._detect_full_mode(client)
        self._bootstrap_busy = False
        self._auto_install_busy = False
        self._bootstrap_ran = False
        self._schedule_installed = False
        self._finish_pending = False

        self.dialog = Adw.Window()
        self.dialog.set_title("oysterAV Setup")
        self.dialog.set_transient_for(window)
        self.dialog.set_modal(True)
        self.dialog.set_default_size(860, 580)

        self._build_shell()
        self._build_pages()

    @property
    def assistant(self) -> Adw.Window:
        """Parent window for modal dialogs (replaces deprecated Gtk.Assistant)."""
        return self.dialog

    @staticmethod
    def _detect_full_mode(client: OystClient) -> bool:
        try:
            config = client.config_get()
            if isinstance(config, dict):
                runtime = config.get("runtime", {})
                if isinstance(runtime, dict):
                    mode = runtime.get("mode", "full")
                    return str(mode) == "full"
        except RuntimeError:
            pass
        return True

    def _set_status(self, text: str) -> None:
        if self._on_status:
            self._on_status(text)

    def _emit_changed(self) -> None:
        if self._on_changed:
            self._on_changed()

    def _selected_schedule(self) -> tuple[str, str, str]:
        profiles = ["quick", "full", "integrity", "suite"]
        freqs = ["hourly", "daily", "weekly"]
        p_idx = int(self.wizard_sched_profile.get_selected())
        f_idx = int(self.wizard_sched_frequency.get_selected())
        profile = profiles[p_idx] if 0 <= p_idx < len(profiles) else "quick"
        frequency = freqs[f_idx] if 0 <= f_idx < len(freqs) else "daily"
        at_time = self.wizard_sched_time.get_text().strip() or "02:00"
        return profile, frequency, at_time

    def _apply_schedule_ui(self, status: dict[str, Any]) -> None:
        present = timer_is_present(status)
        self._schedule_installed = present
        self.schedule_label.set_text(format_timer_status(status))
        profile, frequency, _at = self._selected_schedule()
        self.schedule_btn.set_label(
            schedule_timer_button_label(
                present=present,
                profile=profile,
                frequency=frequency,
            ),
        )
        self._refresh_ready_summary()

    def _refresh_ready_summary(self) -> None:
        if not hasattr(self, "ready_summary"):
            return
        self.ready_summary.set_text(
            format_ready_checklist(
                self._setup,
                bootstrap_ran=self._bootstrap_ran,
                schedule_installed=self._schedule_installed,
                auto_quarantine=self.auto_quarantine.get_active(),
                full_mode=self._full_mode,
            ),
        )

    def _build_shell(self) -> None:
        header = Adw.HeaderBar()
        self._cancel_btn = make_button("Cancel")
        self._cancel_btn.connect("clicked", self._on_cancel_clicked)
        header.pack_start(self._cancel_btn)

        self._back_btn = make_button("Back")
        self._back_btn.connect("clicked", self._on_back_clicked)
        header.pack_start(self._back_btn)

        self._next_btn = make_button("Next", suggested=True)
        self._next_btn.connect("clicked", self._on_next_clicked)
        header.pack_end(self._next_btn)

        self._sidebar = Gtk.ListBox()
        self._sidebar.set_size_request(180, -1)
        self._sidebar.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self._sidebar.add_css_class("navigation-sidebar")
        for title in PAGE_TITLES:
            row = Gtk.ListBoxRow()
            row.set_child(Gtk.Label(label=title, xalign=0, margin_start=12, margin_end=12))
            row.set_selectable(False)
            row.set_activatable(False)
            self._sidebar.append(row)

        self._stack = Gtk.Stack()
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True)
        paned.set_start_child(self._sidebar)
        paned.set_end_child(self._stack)
        paned.set_shrink_start_child(False)
        paned.set_shrink_end_child(False)
        paned.set_resize_start_child(False)
        paned.set_resize_end_child(True)
        paned.set_position(190)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        body.append(paned)
        body.set_vexpand(True)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.set_content(body)
        self.dialog.set_content(toolbar)

    def _build_pages(self) -> None:
        welcome_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        welcome_box.set_margin_top(12)
        welcome_box.set_margin_start(12)
        welcome_box.set_margin_end(12)
        welcome_desc = Gtk.Label(
            label=(
                "oysterAV orchestrates ClamAV, rkhunter, and other Linux security tools.\n"
                "This wizard checks your system, helps install missing packs, "
                "and runs first-time maintenance.\n\n"
                "In full delivery mode, security tools are installed to a private runtime "
                "under ~/.local/share/oysterav/runtime/.\n\n"
                "Auto-Install uses recommended defaults: quick profile, daily at 02:00, "
                "linger enabled, and full runtime bootstrap. "
                "Use Next to choose packs, quarantine, and schedule yourself."
            ),
            xalign=0,
            wrap=True,
        )
        welcome_desc.add_css_class("dim-label")
        welcome_box.append(welcome_desc)
        self.welcome_status = Gtk.Label(label="", xalign=0, wrap=True)
        self.welcome_status.add_css_class("dim-label")
        welcome_box.append(self.welcome_status)
        self.auto_install_btn = make_button("Auto-Install", suggested=True)
        self.auto_install_btn.connect("clicked", self._on_auto_install)
        welcome_box.append(self.auto_install_btn)
        self._stack.add_named(self._wrap_scrolled(welcome_box), "page-0")

        packs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        packs_box.set_margin_top(12)
        packs_box.set_margin_start(12)
        packs_box.set_margin_end(12)

        status_heading = make_section_heading("Status")
        packs_box.append(status_heading)
        packs_desc = Gtk.Label(
            label="Check which security tools are present, then install any that are missing.",
            xalign=0,
            wrap=True,
        )
        packs_desc.add_css_class("dim-label")
        packs_box.append(packs_desc)
        self.check_spinner = Gtk.Spinner()
        spinner_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        spinner_row.append(self.check_spinner)
        spinner_row.append(Gtk.Label(label="Checking installed security packs…", xalign=0))
        packs_box.append(spinner_row)
        self.check_label = Gtk.Label(label="Running doctor…", xalign=0, wrap=True)
        self.check_label.add_css_class("dim-label")
        packs_box.append(self.check_label)
        self.runtime_status_label = Gtk.Label(label="Mode: — · Disk: —", xalign=0, wrap=True)
        self.runtime_status_label.add_css_class("dim-label")
        packs_box.append(self.runtime_status_label)
        refresh_btn = make_button("Refresh status")
        refresh_btn.connect("clicked", self._on_recheck_clicked)
        packs_box.append(refresh_btn)

        packs_heading = make_section_heading("Packs")
        packs_box.append(packs_heading)
        self.install_warning = Adw.Banner(title="Required packs are still missing.")
        self.install_warning.set_button_label("Continue anyway")
        self.install_warning.set_revealed(False)
        self.install_warning.connect("button-clicked", self._on_install_skip)
        packs_box.append(self.install_warning)
        self.pack_list = PackListWidget(
            self.client,
            window=self._parent_window,
            dialog_parent=self.dialog,
            on_status=self._on_status,
            on_changed=self._on_packs_changed,
            full_mode=self._full_mode,
        )
        packs_box.append(self.pack_list.as_container())

        bootstrap_heading = make_section_heading("Bootstrap")
        packs_box.append(bootstrap_heading)
        bootstrap_desc = Gtk.Label(
            label="Install the private runtime, update virus signatures, "
            "and refresh the rkhunter baseline. "
            "You can also do this later under Settings → Maintenance.",
            xalign=0,
            wrap=True,
        )
        bootstrap_desc.add_css_class("dim-label")
        packs_box.append(bootstrap_desc)
        self.bootstrap_label = Gtk.Label(label="", xalign=0, wrap=True)
        self.bootstrap_label.add_css_class("dim-label")
        packs_box.append(self.bootstrap_label)
        self.bootstrap_primary_btn = make_button(
            "Install runtime and update signatures",
            suggested=True,
        )
        self.bootstrap_primary_btn.connect("clicked", self._on_full_bootstrap)
        packs_box.append(self.bootstrap_primary_btn)
        self.bootstrap_secondary_btn = make_button("Maintenance only")
        self.bootstrap_secondary_btn.connect("clicked", self._on_bootstrap_only)
        packs_box.append(self.bootstrap_secondary_btn)

        self._stack.add_named(self._wrap_scrolled(packs_box), "page-1")

        prefs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        prefs_box.set_margin_top(12)
        prefs_box.set_margin_start(12)
        prefs_box.set_margin_end(12)
        prefs_desc = Gtk.Label(
            label="Choose default scan settings. You can change these later in Settings.",
            xalign=0,
            wrap=True,
        )
        prefs_desc.add_css_class("dim-label")
        prefs_box.append(prefs_desc)
        prefs_group = Adw.PreferencesGroup(title="Scan defaults")
        self.auto_quarantine = Adw.SwitchRow(title="Auto-quarantine threats")
        self.auto_quarantine.connect("notify::active", lambda *_: self._refresh_ready_summary())
        prefs_group.add(self.auto_quarantine)
        prefs_box.append(prefs_group)
        self._stack.add_named(self._wrap_scrolled(prefs_box), "page-2")

        services_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        services_box.set_margin_top(12)
        services_box.set_margin_start(12)
        services_box.set_margin_end(12)
        schedule_desc = Gtk.Label(
            label="Choose schedule preferences, then install the systemd user timer. "
            "Auto-Install uses quick / daily / 02:00 instead of these controls. "
            "You can change the timer later in Settings → Scheduling.",
            xalign=0,
            wrap=True,
        )
        schedule_desc.add_css_class("dim-label")
        services_box.append(schedule_desc)
        sched_group = Adw.PreferencesGroup(title="Scheduled scan")
        self.wizard_sched_profile = Adw.ComboRow(title="Profile")
        bind_string_combo_row(
            self.wizard_sched_profile,
            ["quick", "full", "integrity", "suite"],
        )
        self.wizard_sched_profile.connect(
            "notify::selected",
            lambda *_: self._on_schedule_prefs_changed(),
        )
        sched_group.add(self.wizard_sched_profile)
        self.wizard_sched_frequency = Adw.ComboRow(title="Frequency")
        bind_string_combo_row(
            self.wizard_sched_frequency,
            ["hourly", "daily", "weekly"],
        )
        self.wizard_sched_frequency.set_selected(1)
        self.wizard_sched_frequency.connect(
            "notify::selected",
            lambda *_: self._on_schedule_prefs_changed(),
        )
        sched_group.add(self.wizard_sched_frequency)
        self.wizard_sched_time = Adw.EntryRow(title="Time (HH:MM)")
        self.wizard_sched_time.set_text("02:00")
        self.wizard_sched_time.set_show_apply_button(False)
        sched_group.add(self.wizard_sched_time)
        services_box.append(sched_group)
        self.schedule_label = Gtk.Label(label="", xalign=0, wrap=True)
        self.schedule_label.add_css_class("dim-label")
        services_box.append(self.schedule_label)
        self.schedule_btn = make_button("Install quick daily-scan timer")
        self.schedule_btn.connect("clicked", self._on_schedule_install)
        services_box.append(self.schedule_btn)
        self._stack.add_named(self._wrap_scrolled(services_box), "page-3")

        ready_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        ready_box.set_margin_top(12)
        ready_box.set_margin_start(12)
        ready_box.set_margin_end(12)
        ready_heading = make_section_heading("Summary")
        ready_box.append(ready_heading)
        self.ready_summary = Gtk.Label(label="", xalign=0, wrap=True)
        self.ready_summary.add_css_class("dim-label")
        ready_box.append(self.ready_summary)
        ready_desc = Gtk.Label(
            label=(
                "Finish marks setup complete. You can reopen this wizard from "
                "Settings → Maintenance."
            ),
            xalign=0,
            wrap=True,
        )
        ready_desc.add_css_class("dim-label")
        ready_box.append(ready_desc)
        scan_btn = make_button("Open Scan tab", suggested=True)
        scan_btn.connect("clicked", self._on_open_scan)
        ready_box.append(scan_btn)
        self._stack.add_named(self._wrap_scrolled(ready_box), "page-4")

        self._go_to_page(0)

    def _wrap_scrolled(self, content: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_child(content)
        scroll.set_vexpand(True)
        return scroll

    def present(self) -> None:
        self.dialog.present()
        GLib.idle_add(self._after_present)

    def _after_present(self) -> bool:
        self._load_preferences()
        self._run_doctor()
        self._refresh_schedule_status()
        return False

    def _load_preferences(self) -> None:
        try:
            val = self.client.config_get("quarantine.auto")
            self.auto_quarantine.set_active(str(val).lower() in ("true", "1", "yes"))
        except RuntimeError as exc:
            self._set_status(f"Could not load preferences: {exc}")

    def _run_doctor(self) -> None:
        self._doctor_running = True
        self._doctor_done = False
        self.check_spinner.start()
        self.check_label.set_text(format_check_summary(self._setup, running=True))
        self._update_nav()

        def worker() -> dict[str, Any]:
            packs = self.client.doctor()
            setup = self.client.setup_status()
            try:
                runtime = self.client.runtime_status()
            except RuntimeError:
                runtime = {}
            return {"packs": packs, "setup": setup, "runtime": runtime}

        run_in_thread(worker, self._apply_doctor, self._apply_doctor_error)

    def _apply_doctor(self, data: dict[str, Any]) -> bool:
        self._packs = list(data.get("packs", []))
        self._setup = dict(data.get("setup", {}))
        runtime = data.get("runtime") if isinstance(data.get("runtime"), dict) else {}
        self.pack_list.set_packs(self._packs, runtime=runtime)
        self.runtime_status_label.set_text(
            format_runtime_status_line(runtime) if runtime else "Mode: — · Disk: —",
        )
        self._doctor_running = False
        self._doctor_done = True
        self.check_spinner.stop()
        self.check_label.set_text(format_check_summary(self._setup))
        self.welcome_status.set_text(format_check_summary(self._setup))
        self._refresh_install_gate()
        self._refresh_ready_summary()
        self._update_nav()
        return False

    def _apply_doctor_error(self, message: str) -> bool:
        self._doctor_running = False
        self._doctor_done = True
        self.check_spinner.stop()
        self.check_label.set_text(f"Doctor failed: {message}")
        self.welcome_status.set_text(f"Doctor failed: {message}")
        self._update_nav()
        return False

    def _on_recheck_clicked(self, *_args: object) -> None:
        self._run_doctor()

    def _on_packs_changed(self) -> None:
        self._packs = self.pack_list.get_packs()
        try:
            self._setup = self.client.setup_status()
        except RuntimeError as exc:
            self._set_status(f"Could not refresh setup status: {exc}")
        self._refresh_install_gate()
        self.check_label.set_text(format_check_summary(self._setup))
        self.welcome_status.set_text(format_check_summary(self._setup))
        self._refresh_ready_summary()
        self._update_nav()
        self._emit_changed()

    def _refresh_install_gate(self) -> None:
        missing = list(self._setup.get("missing_required") or [])
        reveal = bool(missing) and not self._install_skipped
        self.install_warning.set_title(
            f"Required packs still missing: {', '.join(missing)}. "
            "Continue anyway lets you finish setup; the wizard will not keep "
            "reopening for those packs.",
        )
        self.install_warning.set_button_label("Continue anyway")
        self.install_warning.set_revealed(reveal)

    def _on_schedule_prefs_changed(self) -> None:
        profile, frequency, _at = self._selected_schedule()
        self.schedule_btn.set_label(
            schedule_timer_button_label(
                present=self._schedule_installed,
                profile=profile,
                frequency=frequency,
            ),
        )

    def _refresh_schedule_status(self) -> None:
        def done(status: dict[str, Any]) -> bool:
            self._apply_schedule_ui(status)
            return False

        run_in_thread(lambda: self.client.schedule_status(), done, lambda _m: False)

    def _can_advance(self) -> bool:
        if self._current == 1:
            if not self._doctor_done or self._doctor_running:
                return False
            missing = list(self._setup.get("missing_required") or [])
            return not missing or self._install_skipped
        return True

    def _go_to_page(self, index: int) -> None:
        self._current = max(0, min(index, len(PAGE_TITLES) - 1))
        self._stack.set_visible_child_name(f"page-{self._current}")
        row = self._sidebar.get_row_at_index(self._current)
        if row is not None:
            self._sidebar.select_row(row)
        if self._current == len(PAGE_TITLES) - 1:
            self._refresh_ready_summary()
        self._update_nav()

    def _update_nav(self) -> None:
        busy = self._auto_install_busy or self._bootstrap_busy or self._finish_pending
        self._back_btn.set_sensitive(self._current > 0 and not busy)
        on_last = self._current == len(PAGE_TITLES) - 1
        self._next_btn.set_label("Finish" if on_last else "Next")
        self._next_btn.set_sensitive((self._can_advance() or on_last) and not busy)
        self._cancel_btn.set_sensitive(not busy)
        self.auto_install_btn.set_sensitive(not self._auto_install_busy)

    def _on_back_clicked(self, *_args: object) -> None:
        if self._current > 0:
            self._go_to_page(self._current - 1)

    def _on_next_clicked(self, *_args: object) -> None:
        if self._current == len(PAGE_TITLES) - 1:
            self._finish_setup(mark_complete=True)
            return
        if not self._can_advance():
            return
        self._go_to_page(self._current + 1)

    def _on_cancel_clicked(self, *_args: object) -> None:
        if self._auto_install_busy:
            return
        self._finish_setup(mark_complete=False)

    def _on_auto_install(self, *_args: object) -> None:
        if self._auto_install_busy:
            return
        self._load_preferences()
        self._auto_install_busy = True
        self.welcome_status.set_text("Running Auto-Install with recommended defaults…")
        self._set_status("Running Auto-Install…")
        self._update_nav()
        auto_quarantine = self.auto_quarantine.get_active()

        def worker() -> dict[str, Any]:
            return self.client.setup_run(
                confirm_aur=True,
                enable_linger=True,
                auto_quarantine=auto_quarantine,
            )

        def done(result: dict[str, Any]) -> bool:
            self._auto_install_busy = False
            completed = bool(result.get("completed"))
            ok = bool(result.get("ok"))
            steps_ok = result.get("steps_ok", 0)
            steps_total = result.get("steps_total", 0)
            if completed and ok:
                summary = f"Auto-Install finished ({steps_ok}/{steps_total} steps OK)."
                self.welcome_status.set_text(summary)
                self._set_status(summary)
                self._bootstrap_ran = True
                self._refresh_schedule_status()
                self._run_doctor()
                self._go_to_page(len(PAGE_TITLES) - 1)
                self._emit_changed()
                if self._on_complete:
                    self._on_complete()
            else:
                summary = f"Auto-Install finished with issues ({steps_ok}/{steps_total} steps OK)."
                self.welcome_status.set_text(summary)
                self._set_status(summary)
                body = summary
                failed = [
                    step
                    for step in result.get("steps", [])
                    if isinstance(step, dict) and not step.get("ok") and not step.get("skipped")
                ]
                if failed:
                    details = []
                    for step in failed[:5]:
                        name = str(step.get("step", "?"))
                        message = str(step.get("message", "")).strip()
                        if message:
                            details.append(f"{name}: {message[:200]}")
                        else:
                            details.append(name)
                    body = f"{summary}\n\n" + "\n".join(details)
                show_command_dialog(
                    self.dialog,
                    heading="Auto-Install completed with issues",
                    body=body,
                    copy_text="oyst-cli setup run --enable-linger",
                )
                self._refresh_schedule_status()
                self._run_doctor()
                self._emit_changed()
                if completed:
                    self._bootstrap_ran = True
                    self._go_to_page(len(PAGE_TITLES) - 1)
                    if self._on_complete:
                        self._on_complete()
                else:
                    self._update_nav()
            return False

        def fail(message: str) -> bool:
            self._auto_install_busy = False
            self.welcome_status.set_text(f"Auto-Install failed: {message}")
            self._set_status(f"Auto-Install failed: {message}")
            self._update_nav()
            show_command_dialog(
                self.dialog,
                heading="Auto-Install failed",
                body=message,
                copy_text="oyst-cli setup run --enable-linger",
            )
            return False

        run_in_thread(worker, done, fail)

    def _on_install_skip(self, *_args: object) -> None:
        self._install_skipped = True
        self.install_warning.set_revealed(False)
        try:
            self.client.config_set("setup.skipped_steps", "required_packs")
            self._setup = self.client.setup_status()
        except RuntimeError as exc:
            self._set_status(f"Could not record skipped packs: {exc}")
        self._refresh_ready_summary()
        self._update_nav()

    def _set_bootstrap_busy(self, busy: bool) -> None:
        self._bootstrap_busy = busy
        self.bootstrap_primary_btn.set_sensitive(not busy)
        self.bootstrap_secondary_btn.set_sensitive(not busy)
        self._update_nav()

    def _on_full_bootstrap(self, *_args: object) -> None:
        if self._bootstrap_busy:
            return
        self._set_bootstrap_busy(True)
        self.bootstrap_label.set_text("Installing runtime, updating signatures, running bootstrap…")

        def on_complete(steps: list[dict[str, Any]]) -> None:
            ok_count = sum(1 for r in steps if r.get("ok"))
            self.bootstrap_label.set_text(
                f"Full bootstrap finished ({ok_count}/{len(steps)} steps OK).",
            )
            self._bootstrap_ran = ok_count > 0
            self._set_bootstrap_busy(False)
            self._run_doctor()
            self._emit_changed()

        def on_error(message: str) -> None:
            self.bootstrap_label.set_text(f"Bootstrap failed: {message}")
            self._set_bootstrap_busy(False)

        bootstrap_runtime_from_gui(
            self.client,
            window=self._parent_window,
            parent=self.dialog,
            on_status=self._set_status,
            on_complete=on_complete,
            on_error=on_error,
            update_signatures=True,
            run_maintenance=True,
            progress_button=self.bootstrap_primary_btn,
            progress_verb="Installing",
        )

    def _on_bootstrap_only(self, *_args: object) -> None:
        if self._bootstrap_busy:
            return
        self._set_bootstrap_busy(True)
        self.bootstrap_label.set_text("Running maintenance bootstrap…")

        def done(steps: list[dict[str, object]]) -> bool:
            ok_count = sum(1 for s in steps if s.get("ok"))
            self.bootstrap_label.set_text(
                f"Maintenance finished ({ok_count}/{len(steps)} steps OK).",
            )
            self._bootstrap_ran = ok_count > 0
            self._set_bootstrap_busy(False)
            self._run_doctor()
            self._emit_changed()
            return False

        def on_error(message: str) -> bool:
            self._set_bootstrap_busy(False)
            self.bootstrap_label.set_text(f"Maintenance failed: {message}")
            return False

        run_in_thread(
            lambda: self.client.maintenance_bootstrap(skip_lynis=True),
            done,
            on_error,
        )

    def _on_schedule_install(self, *_args: object) -> None:
        profile, frequency, at_time = self._selected_schedule()

        self.schedule_label.set_text("Installing scheduled scan timer…")
        self.schedule_btn.set_sensitive(False)

        def worker() -> dict[str, Any]:
            self.client.config_set("schedule.profile", profile)
            self.client.config_set("schedule.frequency", frequency)
            self.client.config_set("schedule.time", at_time)
            self.client.config_set("schedule.enabled", "true")
            return self.client.schedule_apply(smoke_test=True)

        def on_complete(result: dict[str, Any]) -> bool:
            self.schedule_btn.set_sensitive(True)
            show_schedule_result(
                self._parent_window,
                result,
                parent=self.dialog,
                on_status=self._set_status,
                client=self.client,
                on_complete=lambda _r: None,
            )

            def apply_status(status: dict[str, Any]) -> bool:
                self._apply_schedule_ui(status)
                self._emit_changed()
                return False

            def apply_fallback(_message: str) -> bool:
                self._apply_schedule_ui(result)
                self._emit_changed()
                return False

            run_in_thread(self.client.schedule_status, apply_status, apply_fallback)
            return False

        def on_error(message: str) -> bool:
            self.schedule_btn.set_sensitive(True)
            self.schedule_label.set_text(f"Schedule failed: {message}")
            return False

        run_in_thread(worker, on_complete, on_error)

    def _on_open_scan(self, *_args: object) -> None:
        if self._on_navigate:
            self._on_navigate("scan")
        self._finish_setup(mark_complete=True)

    def _finish_gaps(self) -> list[str]:
        gaps: list[str] = []
        if self._full_mode and not self._bootstrap_ran:
            gaps.append("Runtime bootstrap / signatures were not run")
        if not self._schedule_installed:
            gaps.append("Scheduled scan timer was not installed")
        return gaps

    def _finish_setup(self, *, mark_complete: bool = True) -> None:
        if self._dismissed or self._finish_pending:
            return
        if mark_complete:
            gaps = self._finish_gaps()
            if gaps:
                self._confirm_finish_with_gaps(gaps)
                return
        self._complete_finish(mark_complete=mark_complete)

    def _confirm_finish_with_gaps(self, gaps: list[str]) -> None:
        self._finish_pending = True
        self._update_nav()
        body = "You can finish now and configure these later in Settings:\n\n" + "\n".join(
            f"• {g}" for g in gaps
        )
        dialog = Adw.MessageDialog(
            transient_for=self.dialog,
            heading="Finish setup with optional steps pending?",
            body=body,
        )
        dialog.add_response("back", "Go back")
        dialog.add_response("finish", "Finish anyway")
        dialog.set_response_appearance("finish", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("back")
        dialog.set_close_response("back")

        def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
            self._finish_pending = False
            self._update_nav()
            if response == "finish":
                self._complete_finish(mark_complete=True)

        dialog.connect("response", on_response)
        dialog.present()

    def _complete_finish(self, *, mark_complete: bool = True) -> None:
        if self._dismissed:
            return
        self._dismissed = True
        if mark_complete:
            try:
                self.client.setup_run(
                    skip_packs=True,
                    skip_schedule=True,
                    skip_bootstrap=True,
                    auto_quarantine=self.auto_quarantine.get_active(),
                    mark_complete=True,
                )
            except RuntimeError as exc:
                self._set_status(f"Could not mark setup complete: {exc}")
                show_command_dialog(
                    self.dialog,
                    heading="Setup incomplete",
                    body=f"Could not mark setup complete:\n{exc}",
                    copy_text="oyst-cli setup run --skip-packs --skip-schedule --skip-bootstrap",
                )
                self._dismissed = False
                return
        self.dialog.destroy()
        if self._on_complete:
            self._on_complete()
        elif self._on_changed:
            self._on_changed()
