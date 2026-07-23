"""Root-owned privileged helper invoked via polkit (oyst-helper)."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence

from oyst_core.privileged.helper_clamd import _build_clamd_cocontrol_argv
from oyst_core.privileged.helper_concert import (
    run_scan_concert_alias,
    run_setup_concert_alias,
    run_setup_harden_alias,
    run_update_concert_alias,
)
from oyst_core.privileged.helper_fail2ban import (
    _build_fail2ban_argv,
    _persist_fail2ban_ignoreip,
    _run_fail2ban_client,
)
from oyst_core.privileged.helper_firewall import (
    _build_firewall_argv,
    _build_firewalld_argv,
    _build_ufw_argv,
    _has_flag,
    _parse_flag,
)
from oyst_core.privileged.helper_install_script import seal_and_run_install_tarball
from oyst_core.privileged.helper_sealed_scanner import seal_and_run_scanner
from oyst_core.privileged.helper_services import (
    _apply_maldet_monitor_mode,
    _build_maldet_config_argv,
    _build_rkhunter_whitelist_argv,
    _build_systemctl_argv,
    _build_systemctl_up_argv,
)
from oyst_core.privileged.helper_setup_concert import run_setup_concert
from oyst_core.privileged.helper_setup_harden import run_setup_harden
from oyst_core.privileged.helper_validate import (
    ALLOWED_PACKAGE_MANAGERS,
    ALLOWED_SCANNER_BINARIES,
    CLAMONACC_FLAGS,
    PACKAGE_NAME_RE,
    RKHUNTER_FLAGS,
    UNHIDE_MODES,
    USERNAME_RE,
    _validate_clamonacc_argv,
    _validate_install_script,
    _validate_package_manager_argv,
    _validate_package_name,
    _validate_run_argv,
    _validate_scanner_argv,
    _validate_username,
    resolve_trusted_argv,
    resolve_trusted_binary,
)

__all__ = [
    "ALLOWED_PACKAGE_MANAGERS",
    "ALLOWED_SCANNER_BINARIES",
    "CLAMONACC_FLAGS",
    "PACKAGE_NAME_RE",
    "RKHUNTER_FLAGS",
    "UNHIDE_MODES",
    "USERNAME_RE",
    "_apply_maldet_monitor_mode",
    "_build_clamd_cocontrol_argv",
    "_build_fail2ban_argv",
    "_build_firewall_argv",
    "_build_firewalld_argv",
    "_build_maldet_config_argv",
    "_build_rkhunter_whitelist_argv",
    "_build_systemctl_argv",
    "_build_systemctl_up_argv",
    "_build_ufw_argv",
    "_has_flag",
    "_parse_flag",
    "_persist_fail2ban_ignoreip",
    "_run_fail2ban_client",
    "_validate_clamonacc_argv",
    "_validate_install_script",
    "_validate_package_manager_argv",
    "_validate_package_name",
    "_validate_run_argv",
    "_validate_scanner_argv",
    "_validate_username",
    "main",
    "run_helper_argv",
    "run_scan_concert_alias",
    "run_setup_concert",
    "run_setup_harden",
]


def _run_validated(cmd: list[str]) -> int:
    if cmd == ["true"]:
        return 0
    resolved = resolve_trusted_argv(cmd)
    proc = subprocess.run(resolved, check=False, env=_secure_exec_env())
    if os.path.basename(resolved[0]) == "firewall-cmd" and "--permanent" in resolved:
        if proc.returncode == 0:
            reload_bin = resolve_trusted_binary("firewall-cmd")
            reload_proc = subprocess.run(
                [reload_bin, "--reload"],
                check=False,
                env=_secure_exec_env(),
            )
            return reload_proc.returncode
    return proc.returncode


def _secure_exec_env() -> dict[str, str]:
    """Minimal env for root helper exec (fixed PATH)."""
    env = {k: v for k, v in os.environ.items() if k in ("LANG", "LC_ALL", "TZ")}
    env["PATH"] = "/usr/bin:/usr/sbin:/bin:/sbin"
    env["HOME"] = "/root"
    return env


def run_helper_argv(argv: Sequence[str]) -> int:
    if not argv:
        print(
            "usage: oyst-helper run|run-sealed|install-script|firewall|fail2ban|"
            "systemctl|systemctl-up|maldet-config|rkhunter-whitelist|"
            "clamd-cocontrol|setup-harden|setup-concert|scan-concert|update-concert",
            file=sys.stderr,
        )
        return 2
    subcommand = argv[0]
    if subcommand == "setup-concert":
        return run_setup_concert_alias(argv[1:])
    if subcommand == "setup-harden":
        return run_setup_harden_alias(argv[1:])
    if subcommand == "scan-concert":
        return run_scan_concert_alias(argv[1:])
    if subcommand == "update-concert":
        return run_update_concert_alias(argv[1:])
    if subcommand == "run":
        try:
            cmd = resolve_trusted_argv(_validate_run_argv(argv[1:]))
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(cmd, check=False, env=_secure_exec_env())
        return proc.returncode
    if subcommand == "run-sealed":
        if len(argv) < 4:
            print(
                "usage: oyst-helper run-sealed /path/to/runtime/bin <basename> <sha256> [args...]",
                file=sys.stderr,
            )
            return 2
        try:
            return seal_and_run_scanner(argv[1], argv[2], argv[3], list(argv[4:]))
        except (ValueError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    if subcommand == "install-script":
        if len(argv) < 3:
            print(
                "usage: oyst-helper install-script /path/to/maldetect.tar.gz <sha256>",
                file=sys.stderr,
            )
            return 2
        try:
            return seal_and_run_install_tarball(argv[1], argv[2])
        except (ValueError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
    builders = {
        "firewall": _build_firewall_argv,
        "fail2ban": _build_fail2ban_argv,
        "systemctl": _build_systemctl_argv,
        "systemctl-up": _build_systemctl_up_argv,
        "maldet-config": _build_maldet_config_argv,
        "rkhunter-whitelist": _build_rkhunter_whitelist_argv,
        "clamd-cocontrol": _build_clamd_cocontrol_argv,
    }
    if subcommand in builders:
        if subcommand in ("systemctl-up", "maldet-config"):
            print(
                f"oyst-helper: {subcommand} {' '.join(argv[1:])}",
                file=sys.stderr,
            )
        try:
            cmd = builders[subcommand](argv[1:])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return _run_validated(cmd)
    print(f"unknown subcommand: {subcommand}", file=sys.stderr)
    return 2


def main() -> None:
    raise SystemExit(run_helper_argv(sys.argv[1:]))


if __name__ == "__main__":
    main()
