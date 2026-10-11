"""Medium audit fixes: quarantine CLI errors and exact UFW rule deletion."""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from oyst_cli.main import cli
from oyst_core.models import ExitCode
from oyst_core.packs.firewall_ufw_read import parse_ufw_status_entries, ufw_rule_entries_from_files


class _Vault:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def restore(self, _entry_id: int) -> Any:
        raise self._exc

    def delete(self, _entry_id: int) -> None:
        raise self._exc

    def get(self, _entry_id: int) -> None:
        return None


@pytest.mark.parametrize("command", ["restore", "delete"])
@pytest.mark.parametrize(
    "exc",
    [KeyError(7), FileNotFoundError("/vault/x"), ValueError("hash mismatch"), RuntimeError("db")],
)
def test_quarantine_errors_emit_json_and_exit_error(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    exc: Exception,
) -> None:
    monkeypatch.setattr("oyst_cli.commands.quarantine.QuarantineVault", lambda: _Vault(exc))
    result = CliRunner().invoke(cli, ["quarantine", command, "7", "--confirm", "--json"])
    assert result.exit_code == ExitCode.ERROR, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["entry_id"] == 7
    assert payload["error"]


def test_quarantine_error_text_mode_and_missing_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "oyst_cli.commands.quarantine.QuarantineVault",
        lambda: _Vault(KeyError(3)),
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["quarantine", "restore", "3", "--confirm"])
    assert result.exit_code == ExitCode.ERROR
    assert "entry 3 not found" in result.output
    result = runner.invoke(cli, ["quarantine", "delete", "3", "--dry-run", "--json"])
    assert result.exit_code == ExitCode.ERROR
    assert json.loads(result.output)["ok"] is False


_STATUS = """Status: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    192.0.2.0/24
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
80/tcp                     ALLOW OUT   Anywhere
443                        ALLOW IN    Anywhere
53/udp                     ALLOW IN    192.0.2.5 5353/udp
25/tcp                     DENY IN     Anywhere                   (log)
8080/tcp                   ALLOW IN    2001:db8::/32
"""


def test_status_parser_keeps_source_and_refuses_inexact_rules() -> None:
    entries = {(e["title"], e["from_addr"]): e for e in parse_ufw_status_entries(_STATUS)}
    restricted = entries[("22/tcp · ALLOW", "192.0.2.0/24")]
    assert restricted["removable"] is True
    assert "from 192.0.2.0/24" in restricted["subtitle"]
    anywhere = entries[("22/tcp · ALLOW", None)]
    assert anywhere["removable"] is True
    assert "IPv4+IPv6" in anywhere["subtitle"]
    assert entries[("8080/tcp · ALLOW", "2001:db8::/32")]["removable"] is True
    for title in ("80/tcp · ALLOW", "443 · ALLOW", "53/udp · ALLOW", "25/tcp · DENY"):
        assert entries[(title, None)]["removable"] is False, title


def test_tuple_parser_refuses_interface_dest_and_app_rules(tmp_path: Any) -> None:
    user4 = tmp_path / "user.rules"
    user4.write_text(
        "### tuple ### allow tcp 22 0.0.0.0/0 any 192.0.2.0/24 in\n"
        "### tuple ### allow tcp 23 0.0.0.0/0 any 0.0.0.0/0 in_eth0\n"
        "### tuple ### allow tcp 24 10.0.0.5 any 0.0.0.0/0 in\n"
        "### tuple ### allow tcp 25 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in\n"
        "### tuple ### allow tcp 26 0.0.0.0/0 any 0.0.0.0/0 out\n",
        encoding="utf-8",
    )
    entries = {e["port"]: e for e in ufw_rule_entries_from_files(user4, tmp_path / "none")}
    assert entries["22"]["removable"] is True
    assert entries["22"]["from_addr"] == "192.0.2.0/24"
    for port in ("23", "24", "25", "26"):
        assert entries[port]["removable"] is False, port


def test_cli_ufw_delete_passes_from_and_refuses_outbound(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    class _Result:
        ok = True

        def __init__(self) -> None:
            self.__dict__.update({"ok": True, "message": "dry"})

    class _Ops:
        def ufw_rule(self, action: str, **kwargs: Any) -> _Result:
            calls.append({"action": action, **kwargs})
            return _Result()

    monkeypatch.setattr("oyst_cli.commands.packs.firewall_cmd.FirewallOps", _Ops)
    runner = CliRunner()
    base = ["firewall", "ufw", "delete", "--port", "22", "--proto", "tcp", "--dry-run", "--json"]
    result = runner.invoke(cli, [*base, "--from", "192.0.2.0/24"])
    assert result.exit_code == 0, result.output
    assert calls[-1]["from_addr"] == "192.0.2.0/24"
    assert calls[-1]["rule_action"] == "allow"

    calls.clear()
    result = runner.invoke(cli, [*base, "--direction", "out"])
    assert result.exit_code == ExitCode.ERROR
    assert json.loads(result.output)["ok"] is False
    assert calls == []
