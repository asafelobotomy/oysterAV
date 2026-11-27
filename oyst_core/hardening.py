"""Read-only system hardening checks (MAC, audit, boot, kernel, sysctl, USB).

Everything here reads files a normal user can read (``/proc/sys``, ``/sys``, ``/run``) and runs
no programs, so ``oyst-cli status hardening`` is cheap enough for the Security page. A check
that can't be read (for example ``/sys/kernel/security`` is root-only on some distros) says
``unknown`` rather than guessing. Fixing is left to the user or a later, explicit step.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

State = Literal["ok", "warn", "info", "unknown"]

SECURE_BOOT_VAR = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"


@dataclass(frozen=True)
class Check:
    id: str
    group: str
    title: str
    state: State
    detail: str
    fix: str = ""


@dataclass(frozen=True)
class SysctlRule:
    key: str
    want: int
    title: str
    why: str
    at_least: bool = True
    # Another key the kernel combines with this one (it uses the larger value).
    also: str = ""


# The kernel settings the KSPP and distro hardening guides agree on, limited to ones that don't
# break a desktop (no ptrace_scope=2/3, no disabling user namespaces, which Flatpak and browsers
# need). ``want`` is the safe value; ``at_least`` allows stricter ones.
SYSCTL_RULES: tuple[SysctlRule, ...] = (
    SysctlRule(
        "kernel.kptr_restrict",
        1,
        "Kernel pointers hidden",
        "Hides kernel addresses from users, which exploits use to find their target.",
    ),
    SysctlRule(
        "kernel.dmesg_restrict",
        1,
        "Kernel log restricted",
        "Only admins can read the kernel log, which can leak addresses.",
    ),
    SysctlRule(
        "kernel.yama.ptrace_scope",
        1,
        "Process snooping limited",
        "A program can only debug its own children, so malware can't read other apps' memory.",
    ),
    SysctlRule(
        "kernel.unprivileged_bpf_disabled",
        1,
        "Unprivileged BPF off",
        "Stops users loading BPF programs, a common kernel exploit path.",
    ),
    SysctlRule(
        "net.core.bpf_jit_harden",
        2,
        "BPF JIT hardened",
        "Blinds constants in JIT-compiled BPF against JIT spraying.",
    ),
    SysctlRule(
        "kernel.randomize_va_space",
        2,
        "Full memory randomisation",
        "ASLR for stack, libraries and heap.",
    ),
    SysctlRule(
        "kernel.kexec_load_disabled",
        1,
        "Kernel replacement blocked",
        "Stops a root exploit from loading a new kernel without a reboot.",
    ),
    SysctlRule(
        "fs.protected_symlinks",
        1,
        "Symlink attacks blocked",
        "Stops tricks with links in shared folders like /tmp.",
    ),
    SysctlRule(
        "fs.protected_hardlinks",
        1,
        "Hardlink attacks blocked",
        "Users can't hardlink files they don't own.",
    ),
    SysctlRule(
        "fs.protected_fifos",
        1,
        "FIFO attacks blocked",
        "Limits opening other users' pipes in shared folders.",
    ),
    SysctlRule(
        "fs.protected_regular",
        2,
        "Shared-folder file attacks blocked",
        "Limits opening other users' files in shared folders.",
    ),
    SysctlRule(
        "fs.suid_dumpable",
        0,
        "No core dumps from setuid programs",
        "Crashing a privileged program can't leak its memory to a file.",
        at_least=False,
    ),
    SysctlRule(
        "net.ipv4.tcp_syncookies",
        1,
        "SYN flood protection",
        "Keeps the network stack up under a SYN flood.",
    ),
    SysctlRule(
        "net.ipv4.conf.all.rp_filter",
        1,
        "Spoofed packets dropped",
        "Drops packets whose source address can't be routed back.",
        also="net.ipv4.conf.default.rp_filter",
    ),
    SysctlRule(
        "net.ipv4.conf.all.accept_redirects",
        0,
        "ICMP redirects ignored",
        "Other machines can't reroute this one's traffic.",
        at_least=False,
    ),
    SysctlRule(
        "net.ipv6.conf.all.accept_redirects",
        0,
        "IPv6 redirects ignored",
        "Same as above, for IPv6.",
        at_least=False,
    ),
)


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _sysctl_path(root: Path, key: str) -> Path:
    return root / "proc/sys" / key.replace(".", "/")


def check_sysctls(root: Path) -> list[Check]:
    out: list[Check] = []
    for rule in SYSCTL_RULES:
        raw = _read(_sysctl_path(root, rule.key))
        if raw is None or not raw.lstrip("-").isdigit():
            # Not built into this kernel (e.g. kexec, yama): nothing to harden.
            continue
        value = int(raw)
        other = _read(_sysctl_path(root, rule.also)) if rule.also else None
        if other is not None and other.isdigit():
            value = max(value, int(other))
        good = value >= rule.want if rule.at_least else value <= rule.want
        out.append(
            Check(
                id=f"sysctl:{rule.key}",
                group="Kernel settings",
                title=rule.title,
                state="ok" if good else "warn",
                detail=f"{rule.key} = {value}. {rule.why}",
                fix="" if good else f"{rule.key} = {rule.want}",
            )
        )
    return out


def check_mac(root: Path) -> Check:
    lsm = _read(root / "sys/kernel/security/lsm")
    modules = set((lsm or "").split(","))
    enforce = _read(root / "sys/fs/selinux/enforce")
    if enforce == "1":
        return Check("mac", "Access control", "SELinux", "ok", "SELinux is enforcing.")
    if enforce == "0":
        return Check(
            "mac",
            "Access control",
            "SELinux",
            "warn",
            "SELinux is loaded but permissive: it logs, it doesn't block.",
            "setenforce 1, and SELINUX=enforcing in /etc/selinux/config",
        )
    apparmor = _read(root / "sys/module/apparmor/parameters/enabled")
    if apparmor == "Y" and (lsm is None or "apparmor" in modules):
        return Check(
            "mac",
            "Access control",
            "AppArmor",
            "ok",
            "AppArmor is on. Apps with a profile are confined to what they need.",
        )
    detail = (
        "Neither AppArmor nor SELinux is active, so an exploited app can reach everything you can."
    )
    if lsm:
        detail += f" Active security modules: {lsm}."
    return Check(
        "mac",
        "Access control",
        "App confinement (AppArmor or SELinux)",
        "warn" if lsm is not None or apparmor is not None else "unknown",
        detail,
        "Install apparmor, add lsm=landlock,lockdown,yama,integrity,apparmor,bpf to the kernel "
        "command line, enable apparmor.service, then reboot.",
    )


def check_lockdown(root: Path) -> Check:
    raw = _read(root / "sys/kernel/security/lockdown")
    if raw is None:
        return Check(
            "lockdown",
            "Boot and kernel",
            "Kernel lockdown",
            "unknown",
            "Can't read the lockdown state (it needs admin rights here, or the kernel lacks it).",
        )
    mode = next((w.strip("[]") for w in raw.split() if w.startswith("[")), "none")
    if mode == "none":
        return Check(
            "lockdown",
            "Boot and kernel",
            "Kernel lockdown",
            "info",
            "Off: root can still change the running kernel (modules unsigned, /dev/mem).",
            "lockdown=integrity on the kernel command line (needs signed modules, Secure Boot).",
        )
    return Check("lockdown", "Boot and kernel", "Kernel lockdown", "ok", f"Lockdown mode: {mode}.")


def check_secure_boot(root: Path) -> Check:
    efi = root / "sys/firmware/efi"
    if not efi.is_dir():
        return Check(
            "secure_boot",
            "Boot and kernel",
            "Secure Boot",
            "info",
            "This machine boots without UEFI, so there's no Secure Boot.",
        )
    data = _read_bytes(efi / "efivars" / SECURE_BOOT_VAR)
    if not data:
        return Check(
            "secure_boot",
            "Boot and kernel",
            "Secure Boot",
            "unknown",
            "Can't read the Secure Boot state.",
        )
    if data[-1] == 1:
        return Check(
            "secure_boot",
            "Boot and kernel",
            "Secure Boot",
            "ok",
            "On: only signed boot files start.",
        )
    return Check(
        "secure_boot",
        "Boot and kernel",
        "Secure Boot",
        "info",
        "Off: a tampered bootloader or kernel would still start.",
        "Sign your boot files (sbctl) and turn Secure Boot on in the firmware.",
    )


def check_cpu_mitigations(root: Path) -> Check:
    vuln_dir = root / "sys/devices/system/cpu/vulnerabilities"
    try:
        entries = sorted(p for p in vuln_dir.iterdir() if p.is_file())
    except OSError:
        return Check(
            "cpu",
            "Boot and kernel",
            "CPU flaw mitigations",
            "unknown",
            "The kernel doesn't report CPU flaws.",
        )
    open_flaws = [p.name for p in entries if (_read(p) or "").startswith("Vulnerable")]
    if not open_flaws:
        return Check(
            "cpu",
            "Boot and kernel",
            "CPU flaw mitigations",
            "ok",
            f"All {len(entries)} known CPU flaws are mitigated or n/a.",
        )
    return Check(
        "cpu",
        "Boot and kernel",
        "CPU flaw mitigations",
        "warn",
        "Unmitigated: " + ", ".join(open_flaws) + ".",
        "Update the kernel and CPU microcode (intel-ucode / amd-ucode); remove mitigations=off.",
    )


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
        "auditd isn't running, so there's no tamper-evident record of logins and privilege use.",
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
        "Any USB device is trusted as soon as it's plugged in (e.g. a fake keyboard).",
        "Install usbguard, generate a policy from your devices, enable usbguard.service.",
    )


def assess_hardening(root: Path = Path("/")) -> dict[str, Any]:
    """All checks plus counts. ``root`` is for tests (a fake filesystem tree)."""
    checks = [
        check_mac(root),
        check_secure_boot(root),
        check_lockdown(root),
        check_cpu_mitigations(root),
        check_auditd(root),
        check_usbguard(root),
        *check_sysctls(root),
    ]
    counts = {s: sum(1 for c in checks if c.state == s) for s in ("ok", "warn", "info", "unknown")}
    sysctl_fixes = [c.fix for c in checks if c.id.startswith("sysctl:") and c.fix]
    return {
        "ok": True,
        "score": f"{counts['ok']}/{len(checks)}",
        "counts": counts,
        "checks": [asdict(c) for c in checks],
        "sysctl_fixes": sysctl_fixes,
        # oysterAV's own drop-in (oyst_core.hardening_fix), so the page can offer Undo.
        "hardened_by_oysterav": (root / "etc/sysctl.d/90-oysterav-hardening.conf").is_file(),
    }


__all__ = ["SYSCTL_RULES", "Check", "assess_hardening"]
