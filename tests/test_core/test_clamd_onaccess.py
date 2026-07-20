"""Tests for clamd OnAccessPrevention probe (ADR-008 Phase 1–2)."""

from __future__ import annotations

from pathlib import Path

from oyst_core.health import assess_health
from oyst_core.models import PackTier
from oyst_core.packs.clamd_onaccess import (
    classify_onaccess,
    parse_clamd_conf,
    probe_onaccess_prevention,
)


def test_parse_clamd_conf_onaccess_keys() -> None:
    text = """
# comment
User clamav
LocalSocket /run/clamav/clamd.ctl
DisableCache yes
OnAccessIncludePath /home/u/Downloads
OnAccessPrevention yes
OnAccessExcludeUname clamav
"""
    parsed = parse_clamd_conf(text)
    assert parsed["prevention"] is True
    assert parsed["user"] == "clamav"
    assert parsed["include_paths"] == ["/home/u/Downloads"]
    assert parsed["exclude_unames"] == ["clamav"]
    assert parsed["mount_paths"] == []
    assert parsed["disable_cache"] is True
    assert parsed["local_socket"] == "/run/clamav/clamd.ctl"


def test_probe_reports_conflict_sidecars(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("OnAccessPrevention yes\n", encoding="utf-8")
    sidecar = Path(str(conf) + ".rpmnew")
    sidecar.write_text("OnAccessPrevention no\n", encoding="utf-8")
    result = probe_onaccess_prevention(conf_paths=[conf], kernel_ok=True)
    assert str(sidecar) in result["conflict_sidecars"]


def test_health_package_conflict_and_disable_cache() -> None:
    result = assess_health(
        {
            "packs": [{"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True}],
            "clamd_running": True,
            "clamonacc_prevention_requested": False,
            "clamonacc_onaccess": {
                "conf_path": "/etc/clamav/clamd.conf",
                "disable_cache": False,
                "conflict_sidecars": ["/etc/clamav/clamd.conf.rpmnew"],
            },
        },
    )
    codes = {i["code"] for i in result["issues"]}
    assert "clamd_conf_package_conflict" in codes
    assert "clamd_disable_cache_unset" in codes


def test_classify_blocking_vs_mountpath_conflict() -> None:
    assert (
        classify_onaccess(
            {"prevention": True, "mount_paths": []},
            kernel_ok=True,
        )
        == "blocking"
    )
    assert (
        classify_onaccess(
            {"prevention": True, "mount_paths": ["/"]},
            kernel_ok=True,
        )
        == "block_misconfigured"
    )
    assert (
        classify_onaccess(
            {"prevention": False, "mount_paths": []},
            kernel_ok=True,
        )
        == "notify_only"
    )
    assert (
        classify_onaccess(
            {"prevention": True, "mount_paths": []},
            kernel_ok=False,
        )
        == "impossible"
    )


def test_probe_reads_tmp_conf(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text(
        "OnAccessIncludePath /tmp/dl\nOnAccessPrevention yes\n",
        encoding="utf-8",
    )
    result = probe_onaccess_prevention(conf_paths=[conf], kernel_ok=True)
    assert result["classification"] == "blocking"
    assert result["prevention_enforced"] is True
    assert result["conf_path"] == str(conf.resolve())


def test_probe_handoff_when_no_conf(tmp_path: Path) -> None:
    result = probe_onaccess_prevention(conf_paths=[], kernel_ok=True)
    assert result["classification"] == "handoff_required"
    assert result["prevention_enforced"] is False


def test_assess_health_clears_when_enforced() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
        ],
        "clamd_running": True,
        "signature_age_hours": 1,
        "clamonacc_prevention_requested": True,
        "clamonacc_prevention_enforced": True,
        "clamonacc_onaccess": {"classification": "blocking"},
    }
    result = assess_health(status)
    codes = {i["code"] for i in result["issues"]}
    assert "clamonacc_prevention_unmanaged" not in codes
    assert "clamonacc_prevention_misconfigured" not in codes


def test_assess_health_misconfigured_classification() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
        ],
        "clamd_running": True,
        "signature_age_hours": 1,
        "clamonacc_prevention_requested": True,
        "clamonacc_prevention_enforced": False,
        "clamonacc_onaccess": {"classification": "block_misconfigured"},
    }
    result = assess_health(status)
    assert any(i["code"] == "clamonacc_prevention_misconfigured" for i in result["issues"])
