"""Root-owned privileged helper invoked via polkit (oyst-helper)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

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
    open_install_script_fd,
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


def _seal_and_run_install_script(script_path: str, expected_sha256: str) -> int:
    """Copy extract tree to a root-owned seal dir, re-verify install.sh, then exec."""
    script = _validate_install_script(script_path, expected_sha256)
    fd = open_install_script_fd(script_path, expected_sha256)
    os.close(fd)

    seal_dir = "/var/tmp" if Path("/var/tmp").is_dir() else None
    seal_root = Path(tempfile.mkdtemp(prefix="oyst-seal-", dir=seal_dir))
    try:
        os.chmod(seal_root, 0o700)
        dest_dir = seal_root / script.parent.name
        shutil.copytree(script.parent, dest_dir, symlinks=False)
        sealed_script = dest_dir / "install.sh"
        digest = hashlib.sha256(sealed_script.read_bytes()).hexdigest()
        if digest != expected_sha256.lower():
            print("sealed install.sh sha256 mismatch", file=sys.stderr)
            return 2
        bash = resolve_trusted_binary("bash")
        proc = subprocess.run(
            [bash, str(sealed_script)],
            cwd=str(dest_dir),
            check=False,
            env=_secure_exec_env(),
        )
        return proc.returncode
    finally:
        shutil.rmtree(seal_root, ignore_errors=True)


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
            cmd = resolve_trusted_argv(_validate_run_argv(argv[1:]))
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        proc = subprocess.run(cmd, check=False, env=_secure_exec_env())
        return proc.returncode
    if subcommand == "install-script":
        if len(argv) < 3:
            print(
                "usage: oyst-helper install-script /path/to/install.sh <sha256>",
                file=sys.stderr,
            )
            return 2
        try:
            return _seal_and_run_install_script(argv[1], argv[2])
        except (ValueError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
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
