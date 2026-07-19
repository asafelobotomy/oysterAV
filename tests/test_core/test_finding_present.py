"""Pure finding presentation helpers (no GTK)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oysterav.gui.finding_present import (
    apply_finding_cap,
    collapse_findings,
    finding_display_quarantined,
    finding_display_resolved,
    format_pack_breakdown,
    group_by_pack,
    is_propupd_advisory,
    is_quarantinable_path,
    is_resolvable_finding,
    summarize_findings_badge,
)


def _finding(
    *,
    pack: str = "rkhunter",
    message: str = "Warning: demo",
    path: str = "system",
    threat_name: str = "rkhunter-warning",
    severity: str = "medium",
) -> dict[str, Any]:
    return {
        "pack": pack,
        "message": message,
        "path": path,
        "threat_name": threat_name,
        "severity": severity,
    }


def test_summarize_clean_and_handled() -> None:
    assert summarize_findings_badge([]) == "Clean"
    assert summarize_findings_badge([_finding()]) == "1 finding(s)"
    handled = _finding()
    handled["resolved"] = True
    assert summarize_findings_badge([handled]) == "1 handled"
    multi = [_finding(), _finding(message="other")]
    multi[0]["quarantined"] = True
    multi[1]["resolved"] = True
    assert summarize_findings_badge(multi) == "2 handled"


def test_collapse_identical_messages() -> None:
    noise = [_finding(message="grep noise") for _ in range(5)]
    rows = collapse_findings(noise)
    assert len(rows) == 1
    assert rows[0].count == 5


def test_group_by_pack_and_cap() -> None:
    findings = [_finding(pack="rkhunter"), _finding(pack="maldet", message="hit")]
    collapsed = collapse_findings(findings)
    groups = group_by_pack(collapsed)
    assert [p for p, _ in groups] == ["rkhunter", "maldet"]
    many = collapse_findings([_finding(message=f"m{i}") for i in range(120)])
    visible, hidden = apply_finding_cap(many, cap=100, show_all=False)
    assert len(visible) == 100
    assert hidden == 20
    all_rows, hidden2 = apply_finding_cap(many, show_all=True)
    assert len(all_rows) == 120
    assert hidden2 == 0


def test_pack_breakdown_format() -> None:
    assert format_pack_breakdown({"rkhunter": 2, "maldet": 1}) == "rkhunter 2 · maldet 1"


def test_propupd_and_quarantine_guards(tmp_path: Path) -> None:
    advisory = _finding(
        threat_name="rkhunter-advisory",
        message="run --propupd",
        severity="info",
    )
    assert is_propupd_advisory(advisory)
    assert not is_quarantinable_path("system", "maldet")
    assert not is_quarantinable_path("/no/such/file", "maldet")
    real = tmp_path / "eicar"
    real.write_text("x")
    assert is_quarantinable_path(str(real), "maldet")
    assert not is_quarantinable_path(str(real), "rkhunter")


def test_is_resolvable_finding(tmp_path: Path) -> None:
    assert is_resolvable_finding(
        _finding(
            threat_name="rkhunter-ssh",
            message="Warning: The SSH configuration option 'Protocol' has not been set.",
        )
    )
    owned = tmp_path / "egrep"
    owned.write_text("x")
    assert is_resolvable_finding(
        _finding(
            threat_name="rkhunter-script-replacement",
            path=str(owned),
            message="Warning: replaced",
        )
    )
    assert not is_resolvable_finding(_finding(threat_name="rkhunter-warning"))


def test_display_quarantined_and_resolved_flags() -> None:
    raw = _finding(pack="clamav", path="/tmp/x", threat_name="Eicar")
    assert not finding_display_quarantined(raw)
    raw["quarantined"] = True
    assert finding_display_quarantined(raw)
    assert finding_display_quarantined(
        _finding(pack="maldet", path="/tmp/y"),
        vault_paths={"/tmp/y"},
    )
    ssh = _finding(
        threat_name="rkhunter-ssh",
        message="Warning: The SSH configuration option 'Protocol' has not been set.",
    )
    assert finding_display_resolved(ssh, overlay_text="ALLOW_SSH_PROT_V1=2\n")
    assert not finding_display_resolved(ssh, overlay_text="")
