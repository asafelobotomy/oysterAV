"""Page builders for the first-time setup wizard."""

from __future__ import annotations

from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.widgets.common import (
    bind_string_combo_row,
    make_button,
    make_section_heading,
)
from oysterav.gui.widgets.packs import PackListWidget

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def build_pages(wizard: SetupWizard) -> None:
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
    wizard.welcome_status = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.welcome_status.add_css_class("dim-label")
    welcome_box.append(wizard.welcome_status)
    wizard.auto_install_btn = make_button("Auto-Install", suggested=True)
    wizard.auto_install_btn.connect("clicked", wizard._on_auto_install)
    welcome_box.append(wizard.auto_install_btn)
    wizard._stack.add_named(wizard._wrap_scrolled(welcome_box), "page-0")

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
    wizard.check_spinner = Gtk.Spinner()
    spinner_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    spinner_row.append(wizard.check_spinner)
    spinner_row.append(Gtk.Label(label="Checking installed security packs…", xalign=0))
    packs_box.append(spinner_row)
    wizard.check_label = Gtk.Label(label="Running doctor…", xalign=0, wrap=True)
    wizard.check_label.add_css_class("dim-label")
    packs_box.append(wizard.check_label)
    wizard.runtime_status_label = Gtk.Label(label="Mode: — · Disk: —", xalign=0, wrap=True)
    wizard.runtime_status_label.add_css_class("dim-label")
    packs_box.append(wizard.runtime_status_label)
    refresh_btn = make_button("Refresh status")
    refresh_btn.connect("clicked", wizard._on_recheck_clicked)
    packs_box.append(refresh_btn)

    packs_heading = make_section_heading("Packs")
    packs_box.append(packs_heading)
    wizard.install_warning = Adw.Banner(title="Required packs are still missing.")
    wizard.install_warning.set_button_label("Continue anyway")
    wizard.install_warning.set_revealed(False)
    wizard.install_warning.connect("button-clicked", wizard._on_install_skip)
    packs_box.append(wizard.install_warning)
    wizard.pack_list = PackListWidget(
        wizard.client,
        window=wizard._parent_window,
        dialog_parent=wizard.dialog,
        on_status=wizard._on_status,
        on_changed=wizard._on_packs_changed,
        full_mode=wizard._full_mode,
    )
    packs_box.append(wizard.pack_list.as_container())

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
    wizard.bootstrap_label = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.bootstrap_label.add_css_class("dim-label")
    packs_box.append(wizard.bootstrap_label)
    wizard.bootstrap_primary_btn = make_button(
        "Install runtime and update signatures",
        suggested=True,
    )
    wizard.bootstrap_primary_btn.connect("clicked", wizard._on_full_bootstrap)
    packs_box.append(wizard.bootstrap_primary_btn)
    wizard.bootstrap_secondary_btn = make_button("Maintenance only")
    wizard.bootstrap_secondary_btn.connect("clicked", wizard._on_bootstrap_only)
    packs_box.append(wizard.bootstrap_secondary_btn)

    wizard._stack.add_named(wizard._wrap_scrolled(packs_box), "page-1")

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
    wizard.auto_quarantine = Adw.SwitchRow(title="Auto-quarantine threats")
    wizard.auto_quarantine.connect(
        "notify::active",
        lambda *_: wizard._refresh_ready_summary(),
    )
    prefs_group.add(wizard.auto_quarantine)
    prefs_box.append(prefs_group)
    wizard._stack.add_named(wizard._wrap_scrolled(prefs_box), "page-2")

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
    wizard.wizard_sched_profile = Adw.ComboRow(title="Profile")
    bind_string_combo_row(
        wizard.wizard_sched_profile,
        ["quick", "full", "integrity", "suite"],
    )
    wizard.wizard_sched_profile.connect(
        "notify::selected",
        lambda *_: wizard._on_schedule_prefs_changed(),
    )
    sched_group.add(wizard.wizard_sched_profile)
    wizard.wizard_sched_frequency = Adw.ComboRow(title="Frequency")
    bind_string_combo_row(
        wizard.wizard_sched_frequency,
        ["hourly", "daily", "weekly"],
    )
    wizard.wizard_sched_frequency.set_selected(1)
    wizard.wizard_sched_frequency.connect(
        "notify::selected",
        lambda *_: wizard._on_schedule_prefs_changed(),
    )
    sched_group.add(wizard.wizard_sched_frequency)
    wizard.wizard_sched_time = Adw.EntryRow(title="Time (HH:MM)")
    wizard.wizard_sched_time.set_text("02:00")
    wizard.wizard_sched_time.set_show_apply_button(False)
    sched_group.add(wizard.wizard_sched_time)
    services_box.append(sched_group)
    wizard.schedule_label = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.schedule_label.add_css_class("dim-label")
    services_box.append(wizard.schedule_label)
    wizard.schedule_btn = make_button("Install quick daily-scan timer")
    wizard.schedule_btn.connect("clicked", wizard._on_schedule_install)
    services_box.append(wizard.schedule_btn)
    wizard._stack.add_named(wizard._wrap_scrolled(services_box), "page-3")

    ready_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    ready_box.set_margin_top(12)
    ready_box.set_margin_start(12)
    ready_box.set_margin_end(12)
    ready_heading = make_section_heading("Summary")
    ready_box.append(ready_heading)
    wizard.ready_summary = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.ready_summary.add_css_class("dim-label")
    ready_box.append(wizard.ready_summary)
    ready_desc = Gtk.Label(
        label=(
            "Finish marks setup complete. You can reopen this wizard from Settings → Maintenance."
        ),
        xalign=0,
        wrap=True,
    )
    ready_desc.add_css_class("dim-label")
    ready_box.append(ready_desc)
    scan_btn = make_button("Open Scan tab", suggested=True)
    scan_btn.connect("clicked", wizard._on_open_scan)
    ready_box.append(scan_btn)
    wizard._stack.add_named(wizard._wrap_scrolled(ready_box), "page-4")

    wizard._go_to_page(0)
