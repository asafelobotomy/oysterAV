"""Tests for audit path redaction and private file mode."""

from __future__ import annotations

from oyst_core.audit import SecurityAudit, redact_paths


def test_redact_paths_home() -> None:
    assert redact_paths("/home/alice/.local/share/x") == "/home/<redacted>/.local/share/x"
    nested = {"cmd": "/home/bob/bin/oyst-virusevent", "n": 1}
    assert redact_paths(nested) == {"cmd": "/home/<redacted>/bin/oyst-virusevent", "n": 1}


def test_redact_paths_var_home_and_runtime() -> None:
    assert (
        redact_paths("/var/home/alice/.config/oysterav") == "/var/home/<redacted>/.config/oysterav"
    )
    assert redact_paths("/run/user/1000/bus") == "/run/user/<redacted>/bus"
    assert (
        redact_paths("/var/tmp/oysterav-scan/job-abc/out")
        == "/var/tmp/oysterav-<redacted>/job-abc/out"
    )
    assert redact_paths("/tmp/oysterav-xyz/file") == "/tmp/oysterav-<redacted>/file"


def test_security_audit_redacts_on_log(tmp_path) -> None:
    db = tmp_path / "events.db"
    audit = SecurityAudit(db_path=db)
    audit.log(
        "clamav.ensure_virusevent",
        "/home/carol/file",
        success=True,
        data={"cmd": "/home/carol/.local/share/oysterav/oyst-virusevent"},
    )
    entries = audit.list_entries(limit=1)
    assert entries[0]["action"] == "/home/<redacted>/file"
    assert "/home/<redacted>" in str(entries[0]["data"]["cmd"])
    assert db.stat().st_mode & 0o777 == 0o600
