"""Polkit policy XML builder for oyst-helper argv1-scoped actions."""

from __future__ import annotations

import textwrap

HELPER_EXEC_PATH = "/usr/lib/oysterav/oyst-helper"


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
            <annotate key="org.freedesktop.policykit.exec.path">{HELPER_EXEC_PATH}</annotate>
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
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.systemctl-up",
            description="Start or enable oysterAV AV services",
            message=(
                "Authentication is required to start or enable ClamAV and maldet system services"
            ),
            argv1="systemctl-up",
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
            allow_active="auth_admin",
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
            message="Authentication is required to manage fail2ban bans, ignores, and jails",
            argv1="fail2ban",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.maldet-config",
            description="Configure Linux Malware Detect monitor",
            message="Authentication is required to configure or start the maldet monitor",
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
            action_id="io.github.asafelobotomy.helper.clamd-cocontrol",
            description="Apply oysterAV ClamAV host co-control ensures",
            message=(
                "Authentication is required to write ClamAV systemd drop-ins "
                "or surgical OnAccess / VirusEvent keys"
            ),
            argv1="clamd-cocontrol",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.setup-harden",
            description="Apply oysterAV first-run host hardenings",
            message=(
                "Authentication is required to apply recommended ClamAV, "
                "rkhunter, and firewall host hardenings"
            ),
            argv1="setup-harden",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.setup-concert",
            description="Run oysterAV first-run setup concert",
            message=(
                "Authentication is required to install security packs and apply "
                "recommended host hardenings"
            ),
            argv1="setup-concert",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.scan-concert",
            description="Run oysterAV privileged security scanners",
            message=(
                "Authentication is required to run integrity and audit scanners for this scan"
            ),
            argv1="scan-concert",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.install-script",
            description="Run oysterAV vetted install scripts",
            message="Authentication is required to install security tools",
            argv1="install-script",
            allow_active="auth_admin",
        ),
        _action_xml(
            action_id="io.github.asafelobotomy.helper.run-sealed",
            description="Run oysterAV sealed runtime scanners",
            message=(
                "Authentication is required to run a hash-verified copy of an "
                "oysterAV runtime scanner"
            ),
            argv1="run-sealed",
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


__all__ = ["HELPER_EXEC_PATH", "build_polkit_policy"]
