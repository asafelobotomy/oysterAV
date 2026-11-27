"""Read-only hardening checks against a fake /proc + /sys tree."""

from __future__ import annotations

from pathlib import Path

from oyst_core.hardening import SECURE_BOOT_VAR, SYSCTL_RULES, assess_hardening


def _put(root: Path, rel: str, text: str | bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")


def _by_id(data: dict) -> dict[str, dict]:
    return {c["id"]: c for c in data["checks"]}


def test_hardened_machine_is_all_ok(tmp_path: Path) -> None:
    for rule in SYSCTL_RULES:
        _put(tmp_path, "proc/sys/" + rule.key.replace(".", "/"), f"{rule.want}\n")
    _put(tmp_path, "sys/kernel/security/lsm", "landlock,lockdown,yama,integrity,apparmor,bpf")
    _put(tmp_path, "sys/module/apparmor/parameters/enabled", "Y")
    _put(tmp_path, "sys/kernel/security/lockdown", "none [integrity] confidentiality")
    _put(tmp_path, f"sys/firmware/efi/efivars/{SECURE_BOOT_VAR}", b"\x06\x00\x00\x00\x01")
    _put(tmp_path, "sys/devices/system/cpu/vulnerabilities/spectre_v2", "Mitigation: IBRS")
    _put(tmp_path, "sys/devices/system/cpu/vulnerabilities/meltdown", "Not affected")
    _put(tmp_path, "run/auditd.pid", "42")
    (tmp_path / "proc/42").mkdir(parents=True)
    _put(tmp_path, "run/usbguard.pid", "43")
    (tmp_path / "proc/43").mkdir(parents=True)
    data = assess_hardening(tmp_path)
    assert data["counts"]["warn"] == 0, [c for c in data["checks"] if c["state"] != "ok"]
    assert data["counts"]["ok"] == len(data["checks"])
    assert data["sysctl_fixes"] == []


def test_default_desktop_gets_warnings_with_fixes(tmp_path: Path) -> None:
    _put(tmp_path, "proc/sys/kernel/kptr_restrict", "0")
    _put(tmp_path, "proc/sys/fs/suid_dumpable", "2")
    _put(tmp_path, "proc/sys/net/ipv4/conf/all/rp_filter", "0")
    _put(tmp_path, "proc/sys/net/ipv4/conf/default/rp_filter", "2")  # systemd's default
    _put(tmp_path, "sys/kernel/security/lsm", "landlock,lockdown,yama,integrity,bpf")
    _put(tmp_path, "sys/kernel/security/lockdown", "[none] integrity confidentiality")
    _put(tmp_path, f"sys/firmware/efi/efivars/{SECURE_BOOT_VAR}", b"\x06\x00\x00\x00\x00")
    _put(tmp_path, "sys/devices/system/cpu/vulnerabilities/mds", "Vulnerable: Clear CPU buffers")
    (tmp_path / "run/systemd/units").mkdir(parents=True)
    checks = _by_id(assess_hardening(tmp_path))
    assert checks["sysctl:kernel.kptr_restrict"]["state"] == "warn"
    assert checks["sysctl:kernel.kptr_restrict"]["fix"] == "kernel.kptr_restrict = 1"
    assert checks["sysctl:fs.suid_dumpable"]["state"] == "warn"
    assert checks["sysctl:net.ipv4.conf.all.rp_filter"]["state"] == "ok"
    # Keys this kernel doesn't have are left out, not reported as weak.
    assert "sysctl:kernel.kexec_load_disabled" not in checks
    assert checks["mac"]["state"] == "warn"
    assert checks["lockdown"]["state"] == "info"
    assert checks["secure_boot"]["state"] == "info"
    assert checks["cpu"]["state"] == "warn" and "mds" in checks["cpu"]["detail"]
    assert checks["auditd"]["state"] == "info"
    assert checks["usbguard"]["state"] == "info"


def test_unreadable_state_is_unknown(tmp_path: Path) -> None:
    checks = _by_id(assess_hardening(tmp_path))
    assert checks["mac"]["state"] == "unknown"
    assert checks["lockdown"]["state"] == "unknown"
    assert checks["secure_boot"]["state"] == "info"  # no /sys/firmware/efi: BIOS boot
    assert checks["auditd"]["state"] == "unknown"


def test_selinux_permissive_warns(tmp_path: Path) -> None:
    _put(tmp_path, "sys/fs/selinux/enforce", "0")
    assert _by_id(assess_hardening(tmp_path))["mac"]["state"] == "warn"
    _put(tmp_path, "sys/fs/selinux/enforce", "1")
    assert _by_id(assess_hardening(tmp_path))["mac"]["state"] == "ok"
