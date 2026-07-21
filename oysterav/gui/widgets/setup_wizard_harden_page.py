"""Host hardening page builders for the setup wizard."""

from __future__ import annotations

from typing import TYPE_CHECKING

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.widgets.bulk_checklist import (
    add_action_item,
    add_switch_item,
    make_bulk_expander,
)
from oysterav.gui.widgets.clamonacc_ui import (
    ensure_fdpass_from_gui,
    ensure_virusevent_from_gui,
)
from oysterav.gui.widgets.common import make_button, run_in_thread

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard

_HARDEN_SWITCHES: tuple[tuple[str, str, str], ...] = (
    ("harden_clamd", "Ensure clamd", "Start/enable clamd when available"),
    ("harden_fdpass", "Ensure --fdpass", "clamonacc OnAccessMountPath with --fdpass"),
    ("harden_virusevent", "Ensure VirusEvent", "Bridge detections into oysterAV"),
    ("harden_disable_cache", "Ensure DisableCache", "On-access DisableCache drop-in"),
    ("harden_rkhunter", "Ensure rkhunter defaults", "DISABLE_TESTS overlay"),
)


def build_harden_page(wizard: SetupWizard, harden_box: Gtk.Box) -> None:
    harden_desc = Gtk.Label(
        label=(
            "Apply recommended host defaults without editing clamd.conf by hand. "
            "On-access prevention stays on Settings → Real-time after you choose paths."
        ),
        xalign=0,
        wrap=True,
    )
    harden_desc.add_css_class("dim-label")
    harden_box.append(harden_desc)

    wizard.harden_btn = make_button("Apply recommended hardenings", suggested=True)
    wizard.harden_btn.connect("clicked", wizard._on_apply_harden)
    harden_box.append(wizard.harden_btn)

    expander = make_bulk_expander(
        "Steps included in Apply recommended hardenings",
        subtitle="Toggle steps for Apply; use Ensure for a single step",
        expanded=True,
    )
    wizard.harden_switches = {}
    for key, title, subtitle in _HARDEN_SWITCHES:
        row = add_switch_item(expander, title=title, subtitle=subtitle, active=True)
        wizard.harden_switches[key] = row

    add_action_item(
        expander,
        title="Ensure --fdpass",
        subtitle="Same as Settings → Real-time",
        button_label="Ensure",
        on_clicked=lambda: ensure_fdpass_from_gui(
            wizard.client,
            window=wizard.dialog,
            on_status=wizard._set_status,
        ),
    )
    add_action_item(
        expander,
        title="Ensure VirusEvent",
        subtitle="Same as Settings → Real-time",
        button_label="Ensure",
        on_clicked=lambda: ensure_virusevent_from_gui(
            wizard.client,
            window=wizard.dialog,
            on_status=wizard._set_status,
        ),
    )
    add_action_item(
        expander,
        title="Ensure DisableCache",
        subtitle="ClamAV on-access cache drop-in",
        button_label="Ensure",
        on_clicked=lambda: _ensure_disable_cache(wizard),
    )
    harden_box.append(expander)

    harden_group = Adw.PreferencesGroup(title="Host firewall")
    wizard.enable_firewall_row = Adw.SwitchRow(title="Enable host firewall (SSH-safe)")
    wizard.enable_firewall_row.set_subtitle(
        "Enables UFW or firewalld only when an SSH allow can be ensured; never forces lockout",
    )
    wizard.enable_firewall_row.set_active(True)
    harden_group.add(wizard.enable_firewall_row)
    harden_box.append(harden_group)

    wizard.harden_label = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.harden_label.add_css_class("dim-label")
    harden_box.append(wizard.harden_label)


def _ensure_disable_cache(wizard: SetupWizard) -> None:
    def worker() -> dict:
        return wizard.client.clamav_ensure_disable_cache()

    def done(result: dict) -> bool:
        msg = str(result.get("message") or ("OK" if result.get("ok") else "Failed"))
        wizard._set_status(f"DisableCache: {msg}")
        return False

    def fail(message: str) -> bool:
        wizard._set_status(f"DisableCache failed: {message}")
        return False

    run_in_thread(worker, done, fail)


def enabled_harden_step_ids(wizard: SetupWizard) -> list[str]:
    mapping = {
        "harden_clamd": "harden-clamd",
        "harden_fdpass": "harden-fdpass",
        "harden_virusevent": "harden-virusevent",
        "harden_disable_cache": "harden-disable-cache",
        "harden_rkhunter": "harden-rkhunter-defaults",
    }
    switches = getattr(wizard, "harden_switches", {})
    ids = [
        sid
        for key, sid in mapping.items()
        if switches.get(key) is None or switches[key].get_active()
    ]
    if wizard.enable_firewall_row.get_active():
        ids.append("firewall-ensure")
    return ids


__all__ = ["build_harden_page", "enabled_harden_step_ids"]
