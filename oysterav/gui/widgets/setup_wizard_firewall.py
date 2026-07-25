"""Setup wizard Firewall page — choose UFW, firewalld, or keep host as-is."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gtk  # noqa: E402

from oysterav.gui.widgets.common import make_button, run_in_thread

if TYPE_CHECKING:
    from oysterav.gui.widgets.setup_wizard import SetupWizard


def build_firewall_page(wizard: SetupWizard, box: Gtk.Box) -> None:
    desc = Gtk.Label(
        label=(
            "Pick one host firewall manager. UFW and firewalld both use the kernel "
            "Netfilter stack; oysterAV can edit rules for the managed manager only. "
            "Raw nftables stays CLI."
        ),
        xalign=0,
        wrap=True,
    )
    desc.add_css_class("dim-label")
    box.append(desc)

    wizard.firewall_status_label = Gtk.Label(label="Loading…", xalign=0, wrap=True)
    wizard.firewall_status_label.add_css_class("dim-label")
    box.append(wizard.firewall_status_label)

    group = Adw.PreferencesGroup(title="Managed firewall choice")
    wizard.firewall_backend_row = Adw.ComboRow(title="Backend")
    wizard.firewall_backend_row.set_model(
        Gtk.StringList.new(["UFW (recommended)", "firewalld", "Keep host as-is"]),
    )
    group.add(wizard.firewall_backend_row)
    box.append(group)

    wizard.firewall_hint = Gtk.Label(label="", xalign=0, wrap=True)
    wizard.firewall_hint.add_css_class("dim-label")
    box.append(wizard.firewall_hint)

    wizard.firewall_apply_btn = make_button("Apply firewall choice", suggested=True)
    wizard.firewall_apply_btn.connect("clicked", lambda *_: apply_firewall_choice(wizard))
    box.append(wizard.firewall_apply_btn)

    refresh_firewall_page(wizard)


def _choice_to_backend(index: int) -> str:
    return ("ufw", "firewalld", "none")[max(0, min(index, 2))]


def refresh_firewall_page(wizard: SetupWizard) -> None:
    def worker() -> dict[str, Any]:
        return wizard.client.firewall_recommend()

    def done(data: dict[str, Any]) -> bool:
        rec = str(data.get("recommended") or "ufw")
        det_raw = data.get("detect")
        det: dict[str, Any] = det_raw if isinstance(det_raw, dict) else {}
        active = str(det.get("active") or "none")
        conflict = bool(det.get("conflict"))
        ufw_i = bool(det.get("ufw"))
        fwd_i = bool(det.get("firewalld"))
        lines = [
            f"Recommended for this system: {rec}.",
            f"Current: {active}" + (" (conflict)" if conflict else "") + ".",
            f"Installed: UFW={'yes' if ufw_i else 'no'}, firewalld={'yes' if fwd_i else 'no'}.",
        ]
        if active == "nft-direct":
            lines.append(
                "Host may already filter via nftables; enabling UFW/firewalld adds a "
                "managed layer oysterAV can edit.",
            )
        wizard.firewall_status_label.set_label("\n".join(lines))
        titles = [
            f"UFW{' (recommended)' if rec == 'ufw' else ''}",
            f"firewalld{' (recommended)' if rec == 'firewalld' else ''}",
            "Keep host as-is",
        ]
        wizard.firewall_backend_row.set_model(Gtk.StringList.new(titles))
        pref = 0 if rec == "ufw" else 1
        try:
            saved = wizard.client.config_get("firewall.managed_backend")
        except Exception:
            saved = None
        if saved == "firewalld":
            pref = 1
        elif saved == "none":
            pref = 2
        elif saved == "ufw":
            pref = 0
        wizard.firewall_backend_row.set_selected(pref)
        wizard._firewall_detect = det
        wizard.firewall_hint.set_label(
            "Applying stops the other manager if needed, then enables the choice (SSH-safe). "
            "Missing packages are installed in the same authentication prompt.",
        )
        return False

    def fail(message: str) -> bool:
        wizard._set_status(message)
        return False

    run_in_thread(worker, done, fail)


def apply_firewall_choice(wizard: SetupWizard) -> None:
    backend = _choice_to_backend(int(wizard.firewall_backend_row.get_selected()))
    det = getattr(wizard, "_firewall_detect", {}) or {}
    will_install = (backend == "ufw" and not det.get("ufw")) or (
        backend == "firewalld" and not det.get("firewalld")
    )

    def worker() -> dict[str, Any]:
        result = dict(wizard.client.firewall_select(backend))
        try:
            wizard.client.config_set("firewall.managed_backend", backend)
            result["config_ok"] = True
        except Exception as exc:
            result["config_ok"] = False
            result["config_error"] = str(exc)
        return result

    def done(result: dict[str, Any]) -> bool:
        ok = bool(result.get("ok"))
        msg = str(result.get("message") or ("ok" if ok else "failed"))
        if result.get("config_ok") is False:
            ok = False
            msg = f"{msg}; preference not saved: {result.get('config_error') or 'error'}"
        elif result.get("config_ok") and ok:
            msg = f"{msg}; preference saved"
        wizard._set_status(f"Firewall: {msg}")
        refresh_firewall_page(wizard)
        return False

    def fail(message: str) -> bool:
        wizard._set_status(message)
        return False

    def start() -> None:
        run_in_thread(worker, done, fail)

    if not will_install:
        start()
        return

    dialog = Adw.MessageDialog(
        transient_for=wizard.dialog,
        heading=f"Select {backend}?",
        body=(
            f"Will install {backend}, then enable it (SSH-safe). "
            "Authentication is required to change the managed firewall."
        ),
    )
    dialog.add_response("cancel", "Cancel")
    dialog.add_response("apply", "Apply")
    dialog.set_response_appearance("apply", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("cancel")
    dialog.set_close_response("cancel")

    def on_response(_dlg: Adw.MessageDialog, response: str) -> None:
        if response == "apply":
            start()

    dialog.connect("response", on_response)
    dialog.present()


def selected_firewall_backend(wizard: SetupWizard) -> str:
    row = getattr(wizard, "firewall_backend_row", None)
    if row is None:
        return "ufw"
    return _choice_to_backend(int(row.get_selected()))
