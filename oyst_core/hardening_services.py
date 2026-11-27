"""Hardening checks for monitoring services (auditd, USBGuard), split from oyst_core.hardening."""

from __future__ import annotations

from pathlib import Path

from oyst_core.hardening import Check, _read


def _service_running(root: Path, pid_files: tuple[str, ...], unit: str) -> bool | None:
    for rel in pid_files:
        pid = _read(root / rel)
        if pid and pid.isdigit():
            return (root / "proc" / pid).is_dir()
    unit_dir = root / "run/systemd/units"
    if unit_dir.is_dir():
        # systemd publishes invocation ids of running units here (world-readable).
        return any(p.name.startswith(f"invocation:{unit}") for p in unit_dir.iterdir())
    return None


def check_auditd(root: Path) -> Check:
    running = _service_running(root, ("run/auditd.pid",), "auditd.service")
    if running:
        return Check(
            "auditd",
            "Monitoring",
            "Audit log (auditd)",
            "ok",
            "auditd records logins, privilege use and watched files.",
        )
    return Check(
        "auditd",
        "Monitoring",
        "Audit log (auditd)",
        "info" if running is False else "unknown",
        "auditd isn't running, so there's no tamper-evident record of logins and privilege use."
        if running is False
        else "Can't tell whether auditd is running (no service state to read here).",
        "Install audit and enable auditd.service.",
    )


def check_usbguard(root: Path) -> Check:
    running = _service_running(root, ("run/usbguard.pid",), "usbguard.service")
    if running:
        return Check(
            "usbguard",
            "Monitoring",
            "USB device control (USBGuard)",
            "ok",
            "New USB devices are blocked until allowed.",
        )
    return Check(
        "usbguard",
        "Monitoring",
        "USB device control (USBGuard)",
        "info" if running is False else "unknown",
        "Any USB device is trusted as soon as it's plugged in (e.g. a fake keyboard)."
        if running is False
        else "Can't tell whether USBGuard is running (no service state to read here).",
        "Install usbguard, generate a policy from your devices, enable usbguard.service.",
    )
