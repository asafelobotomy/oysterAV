"""Tests for UFW batch helper + privilege plan."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.privilege.recipes_firewall import build_ufw_batch_plan
from oyst_core.privileged.helper_firewall_batch import (
    MAX_BATCH_RULES,
    parse_ufw_batch_rules,
    run_ufw_batch,
)


def test_parse_ufw_batch_rules_ok() -> None:
    rules = parse_ufw_batch_rules(
        [
            '--rule={"action":"allow","port":"443","proto":"tcp"}',
            '--rule={"action":"delete","port":"123","proto":"tcp","rule_action":"allow"}',
        ],
    )
    assert len(rules) == 2
    assert rules[0]["action"] == "allow"
    assert rules[1]["rule_action"] == "allow"


def test_parse_ufw_batch_rejects_unknown_field() -> None:
    with pytest.raises(ValueError, match="unknown"):
        parse_ufw_batch_rules(['--rule={"action":"allow","port":"80","proto":"tcp","x":1}'])


def test_parse_ufw_batch_rejects_oversize() -> None:
    many = [
        f'--rule={{"action":"allow","port":"{i}","proto":"tcp"}}'
        for i in range(1, MAX_BATCH_RULES + 2)
    ]
    with pytest.raises(ValueError, match="limited"):
        parse_ufw_batch_rules(many)


def test_build_ufw_batch_plan_argv() -> None:
    plan = build_ufw_batch_plan(
        [{"action": "allow", "port": "80", "proto": "tcp"}],
    )
    assert plan.argv1 == "firewall"
    assert plan.helper_argv[0:2] == ["ufw", "batch"]
    assert plan.helper_argv[2].startswith("--rule=")
    assert plan.needs_elevation


def test_run_ufw_batch_stop_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str]) -> tuple[int, str]:
        calls.append(cmd)
        if len(calls) == 1:
            return 1, "boom"
        return 0, "ok"

    monkeypatch.setattr(
        "oyst_core.privileged.helper_firewall_batch.resolve_trusted_argv",
        lambda cmd: list(cmd),
    )
    monkeypatch.setattr(
        "oyst_core.privileged.helper_firewall_batch._run_cmd",
        fake_run,
    )
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = run_ufw_batch(
            [
                '--rule={"action":"allow","port":"80","proto":"tcp"}',
                '--rule={"action":"allow","port":"443","proto":"tcp"}',
            ],
        )
    assert rc == 1
    assert len(calls) == 1
    assert "skipped" in buf.getvalue()


def test_ufw_batch_userspace_dry_run() -> None:
    from oyst_core.packs.firewall_batch import ufw_batch

    with patch("oyst_core.packs.firewall_batch.FirewallPack") as pack_cls:
        pack = MagicMock()
        pack.detect.return_value = {"active": "ufw", "conflict": False}
        pack_cls.return_value = pack
        out = ufw_batch(
            [{"action": "allow", "port": "8080", "proto": "tcp"}],
            dry_run=True,
        )
    assert out["ok"] is True
    assert out["dry_run"] is True
    assert len(out["steps"]) == 1


def test_ufw_batch_blocks_ssh_without_force() -> None:
    from oyst_core.packs.firewall_batch import ufw_batch

    with patch("oyst_core.packs.firewall_batch.FirewallPack") as pack_cls:
        pack = MagicMock()
        pack.detect.return_value = {"active": "ufw", "conflict": False}
        pack_cls.return_value = pack
        out = ufw_batch(
            [{"action": "delete", "port": "22", "proto": "tcp", "rule_action": "allow"}],
            force_lockout=False,
        )
    assert out["ok"] is False
    assert "22" in out["message"]
