"""Install oyst-helper and polkit policy for privileged operations."""

from __future__ import annotations

import os
import shutil
import stat
import sys
import textwrap
from pathlib import Path

from oyst_core.privileged.runner import run_command

HELPER_DIR = Path("/usr/lib/oysterav")
HELPER_PATH = HELPER_DIR / "oyst-helper"
# Legacy path from source installs before packaging alignment.
HELPER_PATH_LEGACY = Path("/usr/local/lib/oysterav/oyst-helper")
POLKIT_PATH = Path("/usr/share/polkit-1/actions/io.github.asafelobotomy.policy")

# Bump when action IDs / argv1 annotations / exec.path change (helper-status reports this).
POLICY_VERSION = 4

POLKIT_ACTION_IDS = (
    "io.github.asafelobotomy.helper.systemctl",
    "io.github.asafelobotomy.helper.run",
    "io.github.asafelobotomy.helper.firewall",
    "io.github.asafelobotomy.helper.fail2ban",
    "io.github.asafelobotomy.helper.maldet-config",
    "io.github.asafelobotomy.helper.rkhunter-whitelist",
    "io.github.asafelobotomy.helper.install-script",
)

# Actions that auth grant-service-lifecycle may authorize without a password.
SERVICE_LIFECYCLE_ACTION_IDS = (
    "io.github.asafelobotomy.helper.systemctl",
    "io.github.asafelobotomy.helper.maldet-config",
)

HELPER_SCRIPT = textwrap.dedent(
    """\
    #!{python}
    from oyst_core.privileged.oyst_helper import main
    main()
    """,
)


def _helper_script_text() -> str:
    """Bind the helper to the interpreter that has oyst_core installed."""
    return HELPER_SCRIPT.format(python=sys.executable)


def _action_xml(
    *,
    action_id: str,
    description: str,
    message: str,
    argv1: str,
    allow_active: str,
) -> str:
    return textwrap.dedent(
        f"""\
          <action id="{action_id}">
            <description>{description}</description>
            <message>{message}</message>
            <defaults>
              <allow_any>auth_admin</allow_any>
              <allow_inactive>auth_admin</allow_inactive>
              <allow_active>{allow_active}</allow_active>
            </defaults>
            <annotate key="org.freedesktop.policykit.exec.path">{HELPER_PATH}</annotate>
            <annotate key="org.freedesktop.policykit.exec.argv1">{argv1}</annotate>
            <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
          </action>
        """,
    )


def build_polkit_policy() -> str:
    """Return the shipped polkit policy XML (argv1-scoped actions)."""
    actions = [
        _action_xml(
            action_id="io.github.asafelobotomy.helper.systemctl",
            description="Control oysterAV system services",
            message=(
                "Authentication is required to start or stop ClamAV "
                "and other oysterAV system services"
            ),
            argv1="systemctl",
            allow_active="auth_admin_keep",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.run",
            description="Run oysterAV privileged tools",
            message=(
                "Authentication is required to run privileged security tools "
                "or configure scheduling"
            ),
            argv1="run",
            allow_active="auth_admin_keep",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.firewall",
            description="Change oysterAV firewall configuration",
            message="Authentication is required to change firewall rules",
            argv1="firewall",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.fail2ban",
            description="Change fail2ban via oysterAV",
            message=("Authentication is required to manage fail2ban bans, ignores, and jails"),
            argv1="fail2ban",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.maldet-config",
            description="Configure Linux Malware Detect monitor",
            message=("Authentication is required to configure or start the maldet monitor"),
            argv1="maldet-config",
            allow_active="auth_admin_keep",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.rkhunter-whitelist",
            description="Update oysterAV rkhunter whitelist overlay",
            message=(
                "Authentication is required to whitelist rkhunter finding(s) "
                "in the oysterAV overlay"
            ),
            argv1="rkhunter-whitelist",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.install-script",
            description="Run oysterAV vetted install scripts",
            message="Authentication is required to install security tools",
            argv1="install-script",
            allow_active="auth_admin",
        ),
    ]
    body = "\n".join(actions)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!DOCTYPE policyconfig PUBLIC "
        '"-//freedesktop//DTD polkit Policy Configuration 1.0//EN"\n'
        ' "http://www.freedesktop.org/software/polkit/policyconfig-1.dtd">\n'
        "<policyconfig>\n"
        f"{body}"
        "</policyconfig>\n"
    )


POLKIT_POLICY = build_polkit_policy()


def install_privileged_helper(*, prefix: Path | None = None) -> dict[str, object]:
    """Install helper script and polkit policy (requires root)."""
    if os.geteuid() != 0:
        return {
            "ok": False,
            "message": "Must run as root (sudo oyst-cli install-privileged-helper)",
            "helper_path": "",
            "polkit_path": "",
            "policy_version": POLICY_VERSION,
        }

    helper_dir = prefix / "lib" / "oysterav" if prefix else HELPER_DIR
    helper_path = helper_dir / "oyst-helper"
    polkit_path = (
        prefix / "share" / "polkit-1" / "actions" / "io.github.asafelobotomy.policy"
        if prefix
        else POLKIT_PATH
    )

    try:
        helper_dir.mkdir(parents=True, exist_ok=True)
        helper_path.write_text(_helper_script_text(), encoding="utf-8")
        helper_path.chmod(helper_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if prefix is None:
            bin_link = Path("/usr/bin/oyst-helper")
            bin_link.parent.mkdir(parents=True, exist_ok=True)
            if bin_link.is_symlink() or bin_link.exists():
                bin_link.unlink()
            bin_link.symlink_to(helper_path)
            legacy_bin = Path("/usr/local/bin/oyst-helper")
            if legacy_bin.is_symlink() or legacy_bin.exists():
                try:
                    legacy_bin.unlink()
                except OSError:
                    pass
        polkit_path.parent.mkdir(parents=True, exist_ok=True)
        polkit_path.write_text(build_polkit_policy(), encoding="utf-8")
        if shutil.which("polkitd") and prefix is None:
            run_command(["systemctl", "reload", "polkit"], timeout=15)
    except OSError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "helper_path": str(helper_path),
            "polkit_path": str(polkit_path),
            "policy_version": POLICY_VERSION,
        }

    return {
        "ok": True,
        "message": "Installed oyst-helper and polkit policy",
        "helper_path": str(helper_path),
        "polkit_path": str(polkit_path),
        "policy_version": POLICY_VERSION,
        "actions": list(POLKIT_ACTION_IDS),
    }


def resolve_installed_helper_path() -> Path | None:
    """Prefer /usr/lib, then legacy /usr/local/lib, for an installed oyst-helper."""
    for candidate in (HELPER_PATH, HELPER_PATH_LEGACY):
        if candidate.is_file():
            return candidate
    return None


def helper_status() -> dict[str, object]:
    helper = resolve_installed_helper_path()
    installed = helper is not None and POLKIT_PATH.is_file()
    actions_present: list[str] = []
    policy_text = ""
    if POLKIT_PATH.is_file():
        try:
            policy_text = POLKIT_PATH.read_text(encoding="utf-8")
        except OSError:
            policy_text = ""
        actions_present = [aid for aid in POLKIT_ACTION_IDS if aid in policy_text]
    return {
        "installed": installed,
        "helper_path": str(helper) if helper else str(HELPER_PATH),
        "polkit_path": str(POLKIT_PATH),
        "policy_version": POLICY_VERSION,
        "actions": list(POLKIT_ACTION_IDS),
        "actions_present": actions_present,
        "policy_current": bool(actions_present) and set(actions_present) == set(POLKIT_ACTION_IDS),
    }
