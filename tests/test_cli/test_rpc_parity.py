"""Ensure every RpcServer method has a CLI equivalent."""

from __future__ import annotations

import inspect

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.client import OystClient
from oyst_core.rpc_handlers import RPC_METHODS
from oyst_core.serve import RpcServer

# RpcServer method -> CLI argv (use --help for mutating or arg-heavy commands).
RPC_TO_CLI: dict[str, list[str]] = {
    "status": ["status", "--json"],
    "status.assess": ["status", "assess", "--json"],
    "pack.doctor": ["doctor", "--json"],
    "pack.install": ["packs", "install", "--help"],
    "setup.status": ["setup", "status", "--json"],
    "setup.run": ["setup", "run", "--help"],
    "job.start": ["scan", "--help"],
    "job.cancel": ["job", "cancel", "--help"],
    "job.clear": ["job", "clear", "--help"],
    "job.status": ["job", "status", "--json"],
    "rkhunter.scan": ["rkhunter", "scan", "--help"],
    "rkhunter.update": ["rkhunter", "update", "--help"],
    "rkhunter.propupd": ["rkhunter", "propupd", "--help"],
    "rkhunter.resolve": ["rkhunter", "resolve", "--help"],
    "history.handle_open": ["history", "handle-open", "--help"],
    "history.delete": ["history", "delete", "--help"],
    "history.delete_all": ["history", "delete-all", "--help"],
    "history.export": ["history", "export", "--help"],
    "history.export_all": ["history", "export-all", "--help"],
    "quarantine.list": ["quarantine", "list", "--json"],
    "quarantine.restore": ["quarantine", "restore", "--help"],
    "quarantine.delete": ["quarantine", "delete", "--help"],
    "quarantine.verify": ["quarantine", "verify", "--json"],
    "quarantine.add": ["quarantine", "add", "--help"],
    "desktop.status": ["desktop", "status", "--json"],
    "maintenance.bootstrap": ["maintenance", "bootstrap", "--help"],
    "maintenance.post-update": ["maintenance", "post-update", "--help"],
    "history.list": ["history", "--json"],
    "history.get": ["history", "show", "--help"],
    "audit.list": ["audit", "list", "--json"],
    "terminal.list": ["terminal", "list", "--json"],
    "terminal.clear": ["terminal", "clear", "--help"],
    "terminal.export": ["terminal", "export", "--help"],
    "config.get": ["config", "get", "--json"],
    "config.set": ["config", "set", "--help"],
    "schedule.install": ["schedule", "install", "--help"],
    "schedule.apply": ["schedule", "apply", "--help"],
    "schedule.status": ["schedule", "status", "--json"],
    "schedule.run": ["schedule", "run", "--help"],
    "schedule.linger": ["schedule", "linger", "--json"],
    "schedule.enable_linger": ["schedule", "enable-linger", "--help"],
    "runtime.status": ["runtime", "status", "--json"],
    "runtime.install": ["runtime", "install", "--help"],
    "runtime.remove": ["runtime", "remove", "--help"],
    "runtime.update": ["runtime", "update", "--help"],
    "runtime.bootstrap": ["runtime", "bootstrap", "--help"],
    "firewall.status": ["firewall", "status", "--json"],
    "firewall.ensure_enable": ["firewall", "ensure-enable", "--help"],
    "firewall.set_enabled": ["firewall", "ensure-enable", "--help"],
    "firewall.select": ["firewall", "select", "--help"],
    "firewall.recommend": ["firewall", "recommend", "--help"],
    "firewall.rules": ["firewall", "rules", "--help"],
    "firewall.export": ["firewall", "export", "--help"],
    "firewall.ufw_rule": ["firewall", "ufw", "allow", "--help"],
    "firewall.ufw_batch": ["firewall", "ufw", "batch", "--help"],
    "firewall.ufw_default": ["firewall", "ufw", "default", "--help"],
    "firewall.firewalld_port": ["firewall", "firewalld", "add-port", "--help"],
    "firewall.firewalld_service": ["firewall", "firewalld", "add-service", "--help"],
    "firewall.firewalld_reload": ["firewall", "firewalld", "reload", "--help"],
    "firewall.firewalld_rich_rule": ["firewall", "firewalld", "rich-rule", "--help"],
    "fail2ban.unban": ["fail2ban", "unban", "--help"],
    "fail2ban.status": ["fail2ban", "status", "--json"],
    "fail2ban.banned": ["fail2ban", "banned", "--help"],
    "fail2ban.jail": ["fail2ban", "jail", "--help"],
    "fail2ban.jail_enable": ["fail2ban", "jail-control", "enable", "--help"],
    "fail2ban.jail_disable": ["fail2ban", "jail-control", "disable", "--help"],
    "fail2ban.reload": ["fail2ban", "reload", "--help"],
    "clamav.clamd.ensure": ["clamav", "clamd", "ensure", "--help"],
    "services.status": ["services", "status", "--json"],
    "services.set": ["services", "set", "--help"],
    "auth.status": ["auth", "status", "--json"],
    "helper.install": ["install-privileged-helper", "--help"],
    "auth.grant_service_lifecycle": ["auth", "grant-service-lifecycle", "--help"],
    "auth.revoke_service_lifecycle": ["auth", "revoke-service-lifecycle", "--help"],
    "clamonacc.status": ["clamonacc", "status", "--json"],
    "clamonacc.start": ["clamonacc", "start", "--help"],
    "clamonacc.stop": ["clamonacc", "stop", "--help"],
    "clamonacc.enable": ["clamonacc", "enable", "--help"],
    "clamonacc.disable": ["clamonacc", "disable", "--help"],
    "clamonacc.add_path": ["clamonacc", "paths", "add", "--help"],
    "clamonacc.remove_path": ["clamonacc", "paths", "remove", "--help"],
    "clamonacc.ensure_fdpass": ["clamonacc", "ensure-fdpass", "--help"],
    "clamonacc.ensure_prevention": ["clamonacc", "ensure-prevention", "--help"],
    "virusevent.status": ["virusevent", "status", "--json"],
    "virusevent.ensure": ["virusevent", "ensure", "--help"],
    "clamav.ensure_disable_cache": ["clamav", "ensure-disable-cache", "--help"],
    "news.list": ["news", "list", "--help"],
    "news.refresh": ["news", "refresh", "--help"],
    "updates.check": ["updates", "check", "--json"],
    "updates.apply": ["updates", "apply", "--help"],
}


def test_rpc_methods_documented_in_mapping() -> None:
    assert set(RPC_METHODS) == set(RPC_TO_CLI.keys())


def test_client_fallback_matches_rpc_server() -> None:
    # Both sides must delegate to the shared HANDLERS registry (no divergent if-chains).
    assert "dispatch_rpc" in inspect.getsource(OystClient._local_fallback)
    assert "dispatch_rpc" in inspect.getsource(RpcServer._dispatch)
    assert set(RPC_METHODS) == set(RPC_TO_CLI.keys())


@pytest.mark.parametrize("rpc_method,cli_argv", list(RPC_TO_CLI.items()))
def test_rpc_method_has_cli_command(rpc_method: str, cli_argv: list[str]) -> None:
    _ = rpc_method
    runner = CliRunner()
    result = runner.invoke(cli, cli_argv)
    assert "No such command" not in result.output, result.output
    assert result.exit_code in (0, 1, 2, 4, 5), result.output
