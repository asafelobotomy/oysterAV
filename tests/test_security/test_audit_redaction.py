"""Audit redaction and firewall.mutate hash-only logging."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from oyst_core.audit import SecurityAudit, redact_paths
from oyst_core.packs.firewall_ops import FirewallOps

pytestmark = pytest.mark.security


def test_redact_paths_home_and_runtime() -> None:
    assert "/home/<redacted>" in redact_paths("/home/alice/.local/share/oysterav/x")
    assert "/run/user/<redacted>" in redact_paths("/run/user/1000/oyst.sock")
    nested = {"path": "/home/bob/secret", "n": 2}
    assert redact_paths(nested)["path"] == "/home/<redacted>/secret"


def test_firewall_mutate_audit_hashes_not_raw_rules(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("oyst_core.audit.data_dir", lambda: tmp_path)
    captured: list[tuple] = []

    def _capture(kind, action, *, success, data=None):
        captured.append((kind, action, success, data))

    ops = FirewallOps()
    with patch.object(SecurityAudit, "log", side_effect=_capture):
        ops._audit_mutate(
            "ufw.allow",
            ok=True,
            argv=["ufw", "allow", "22/tcp"],
            before="22/tcp ALLOW IN Anywhere from 203.0.113.5",
            after="22/tcp ALLOW IN Anywhere from 203.0.113.5\n80/tcp ALLOW",
        )
    assert len(captured) == 1
    kind, _action, success, data = captured[0]
    assert kind == "firewall.mutate"
    assert success is True
    assert "before_sha256" in data
    assert "after_sha256" in data
    assert data["changed"] is True
    blob = str(data)
    assert "203.0.113.5" not in blob
    assert "ALLOW IN" not in blob
    assert len(data["before_sha256"]) == 64


def test_security_audit_persists_redacted(tmp_path) -> None:
    audit = SecurityAudit(db_path=tmp_path / "events.db")
    audit.log(
        "firewall.mutate",
        "ufw.allow",
        success=True,
        data={
            "argv": ["ufw", "allow"],
            "before_sha256": "a" * 64,
            "after_sha256": "b" * 64,
            "changed": True,
            "note": "/home/dave/rules.txt",
        },
    )
    entry = audit.list_entries(limit=1)[0]
    assert "/home/<redacted>" in str(entry["data"]["note"])
    assert entry["data"]["before_sha256"] == "a" * 64
