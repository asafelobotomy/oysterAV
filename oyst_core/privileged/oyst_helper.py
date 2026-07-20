"""Root-owned privileged helper invoked via polkit (oyst-helper)."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence

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
from oyst_core.privileged.helper_services import (
    _apply_maldet_monitor_mode,
    _build_maldet_config_argv,
    _build_rkhunter_whitelist_argv,
    _build_systemctl_argv,
)
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
    "_build_fail2ban_argv",
    "_build_firewall_argv",
    "_build_firewalld_argv",
    "_build_maldet_config_argv",
    "_build_rkhunter_whitelist_argv",
    "_build_systemctl_argv",
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
]


def _run_validated(cmd: list[str]) -> int:
    if cmd == ["true"]:
        return 0
    proc = subprocess.run(cmd, check=False)
    if cmd[0] == "firewall-cmd" and "--permanent" in cmd and proc.returncode == 0:
        reload_proc = subprocess.run(["firewall-cmd", "--reload"], check=False)
        return reload_proc.returncode
    return proc.returncode


def run_helper_argv(argv: Sequence[str]) -> int:
    if not argv:
        print(
            "usage: oyst-helper run|install-script|firewall|fail2ban|systemctl|"
            "maldet-config|rkhunter-whitelist",
            file=sys.stderr,
        )
        return 2
    subcommand = argv[0]
    if subcommand == "run":
        try:
            cmd = _validate_run_argv(argv[1:])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(cmd, check=False)
        return proc.returncode
    if subcommand == "install-script":
        if len(argv) < 2:
            print("usage: oyst-helper install-script /path/to/install.sh", file=sys.stderr)
            return 2
        try:
            script = _validate_install_script(argv[1])
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(
            ["bash", str(script)],
            cwd=str(script.parent),
            check=False,
        )
        return proc.returncode
    builders = {
        "firewall": _build_firewall_argv,
        "fail2ban": _build_fail2ban_argv,
        "systemctl": _build_systemctl_argv,
        "maldet-config": _build_maldet_config_argv,
        "rkhunter-whitelist": _build_rkhunter_whitelist_argv,
    }
    if subcommand in builders:
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
