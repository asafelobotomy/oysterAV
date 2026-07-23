"""Ensure every OystClient method used by the GTK GUI has a CLI equivalent."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli

# OystClient public methods invoked from oysterav/gui/ → CLI argv (help/json smoke).
GUI_CLIENT_TO_CLI: dict[str, list[str]] = {
    "status": ["status", "--json"],
    "history_list": ["history", "--json"],
    "history_get": ["history", "show", "--help"],
    "quarantine_list": ["quarantine", "list", "--json"],
    "quarantine_restore": ["quarantine", "restore", "--help"],
    "quarantine_delete": ["quarantine", "delete", "--help"],
    "quarantine_verify": ["quarantine", "verify", "--json"],
    "quarantine_add": ["quarantine", "add", "--help"],
    "desktop_status": ["desktop", "status", "--json"],
    "doctor": ["doctor", "--json"],
    "pack_install": ["packs", "install", "--help"],
    "maintenance_bootstrap": ["maintenance", "bootstrap", "--help"],
    "start_scan": ["scan", "--help"],
    "cancel_job": ["job", "cancel", "--help"],
    "job_status": ["job", "status", "--json"],
    "rkhunter_update": ["rkhunter", "update", "--help"],
    "rkhunter_propupd": ["rkhunter", "propupd", "--help"],
    "rkhunter_resolve": ["rkhunter", "resolve", "--help"],
    "history_handle_open": ["history", "handle-open", "--help"],
    "history_delete": ["history", "delete", "--help"],
    "history_delete_all": ["history", "delete-all", "--help"],
    "history_export": ["history", "export", "--help"],
    "history_export_all": ["history", "export-all", "--help"],
    "config_get": ["config", "get", "--json"],
    "config_set": ["config", "set", "--help"],
    "setup_status": ["setup", "status", "--json"],
    "schedule_apply": ["schedule", "apply", "--help"],
    "schedule_run": ["schedule", "run", "--help"],
    "schedule_status": ["schedule", "status", "--json"],
    "linger_status": ["schedule", "linger", "--json"],
    "linger_enable": ["schedule", "enable-linger", "--help"],
    "runtime_status": ["runtime", "status", "--json"],
    "runtime_install": ["runtime", "install", "--help"],
    "runtime_remove": ["runtime", "remove", "--help"],
    "runtime_bootstrap": ["runtime", "bootstrap", "--help"],
    "status_assess": ["status", "assess", "--json"],
    "setup_run": ["setup", "run", "--help"],
    "clamav_clamd_ensure": ["clamav", "clamd", "ensure", "--help"],
    "clamonacc_status": ["clamonacc", "status", "--json"],
    "clamonacc_enable": ["clamonacc", "enable", "--help"],
    "clamonacc_disable": ["clamonacc", "disable", "--help"],
    "clamonacc_add_path": ["clamonacc", "paths", "add", "--help"],
    "clamonacc_remove_path": ["clamonacc", "paths", "remove", "--help"],
    "clamonacc_ensure_fdpass": ["clamonacc", "ensure-fdpass", "--help"],
    "clamonacc_ensure_prevention": ["clamonacc", "ensure-prevention", "--help"],
    "virusevent_ensure": ["virusevent", "ensure", "--help"],
    "clamav_ensure_disable_cache": ["clamav", "ensure-disable-cache", "--help"],
    "news_list": ["news", "list", "--json"],
    "news_refresh": ["news", "refresh", "--help"],
    "updates_check": ["updates", "check", "--json"],
    "updates_apply": ["updates", "apply", "--help"],
    "services_status": ["services", "status", "--json"],
    "services_set": ["services", "set", "--help"],
    "auth_status": ["auth", "status", "--json"],
    "helper_install": ["install-privileged-helper", "--help"],
    "auth_grant_service_lifecycle": ["auth", "grant-service-lifecycle", "--help"],
    "auth_revoke_service_lifecycle": ["auth", "revoke-service-lifecycle", "--help"],
    "audit_list": ["audit", "list", "--json"],
    "maintenance_post_update": ["maintenance", "post-update", "--help"],
    "firewall_status": ["firewall", "status", "--json"],
    "fail2ban_unban": ["fail2ban", "unban", "--help"],
}

# Intentional CLI-first surfaces (no full GUI DSL); documented in gui-contract.
CLI_FIRST_REMAINING: frozenset[str] = frozenset(
    {
        "setup check",
        "setup reset",
        "firewall ufw",
        "firewall firewalld",
        "fail2ban jail-control",
        "fangfrisch",
        "lynis audit",
        "maldet scan",
        "chkrootkit scan",
        "unhide scan",
        "freshclam update",
    }
)

GUI_ROOT = Path(__file__).resolve().parents[2] / "oysterav" / "gui"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _is_client_receiver(node: ast.AST) -> bool:
    """True if *node* is `client` or `*.client` (e.g. self.client)."""
    if isinstance(node, ast.Name) and node.id == "client":
        return True
    return isinstance(node, ast.Attribute) and node.attr == "client"


def _client_methods_used_in_gui() -> set[str]:
    """Discover client.<method> uses: calls and bound-method references.

    Catches both ``client.foo()`` / ``self.client.foo()`` and
    ``run_in_thread(self.client.foo, ...)`` / ``client.foo,``.
    """
    used: set[str] = set()
    for path in GUI_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if _is_client_receiver(node.value):
                used.add(node.attr)
    return used


def test_all_gui_client_methods_documented() -> None:
    used = _client_methods_used_in_gui()
    documented = set(GUI_CLIENT_TO_CLI.keys())
    missing = used - documented
    assert not missing, f"GUI uses undocumented client methods: {sorted(missing)}"


def test_bound_method_refs_are_discovered() -> None:
    """Regression: run_in_thread(self.client.foo) must count as a use of foo."""
    used = _client_methods_used_in_gui()
    # Passed as bound methods (not always called with parentheses in GUI code).
    for method in (
        "clamav_clamd_ensure",
        "clamonacc_enable",
        "clamonacc_disable",
        "clamonacc_status",
        "linger_enable",
        "rkhunter_update",
        "rkhunter_propupd",
        "rkhunter_resolve",
        "news_refresh",
        "quarantine_list",
        "quarantine_verify",
        "job_status",
        "start_scan",
    ):
        assert method in used, f"expected bound-method discovery for {method}"


@pytest.mark.parametrize("client_method,cli_argv", list(GUI_CLIENT_TO_CLI.items()))
def test_gui_client_method_has_cli_command(client_method: str, cli_argv: list[str]) -> None:
    _ = client_method
    runner = CliRunner()
    result = runner.invoke(cli, cli_argv)
    assert "No such command" not in result.output, result.output
    # Allow non-zero exits that still prove the command is registered (e.g. doctor
    # exits 5 when required packs are missing on a bare CI image).
    assert result.exit_code in (0, 1, 2, 4, 5), result.output


def test_helper_auth_use_client_not_gui_pkexec() -> None:
    """Helper install / auth grant elevate via OystClient RPC, not GUI subprocesses."""
    services_ui = (GUI_ROOT / "widgets" / "services_ui.py").read_text(encoding="utf-8")
    assert "request_helper_install" in services_ui
    assert "request_auth_grant" in services_ui
    assert "request_auth_revoke" in services_ui
    assert "pkexec" not in services_ui
    assert "show_command_dialog" not in services_ui
    assert "sudo oyst-cli" not in services_ui


def test_no_security_subprocess_in_gui() -> None:
    """ADR-002: oysterav must not spawn security tools directly."""
    pattern = re.compile(
        r"subprocess\.(run|call|Popen)|os\.system\(|"
        r"\bpkexec\b|\bsystemctl\b.*\bclam|"
        r"Popen\(",
    )
    offenders: list[str] = []
    for path in (REPO_ROOT / "oysterav").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                # Allow string literals used only as copy_text / labels.
                if "copy_text" in line or "label=" in line or 'f"' in line or "subtitle" in line:
                    continue
                if "systemctl/maldet" in line:  # descriptive UI string
                    continue
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not offenders, "forbidden security process patterns:\n" + "\n".join(offenders)


def test_cli_first_remaining_documented_in_contract() -> None:
    contract = (REPO_ROOT / "docs" / "cli" / "gui-contract.md").read_text(encoding="utf-8")
    assert "CLI-first" in contract or "cli-first" in contract.lower()
    assert "helper.install" in contract
    assert "auth.grant_service_lifecycle" in contract
    for item in CLI_FIRST_REMAINING:
        # At least the family name should appear in contract / pack docs.
        token = item.split()[0]
        assert token in contract or token in (
            REPO_ROOT / "docs" / "cli" / "pack-commands.md"
        ).read_text(encoding="utf-8"), f"CLI-first surface {item!r} undocumented"
