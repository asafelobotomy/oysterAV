"""Health assessment tests."""

from __future__ import annotations

from oyst_core.health import assess_health
from oyst_core.models import PackTier


def test_assess_health_ok_when_protected() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
            {"name": "freshclam", "tier": PackTier.REQUIRED.value, "installed": True},
        ],
        "signature_age_hours": 12,
        "clamd_running": True,
        "active_job": None,
    }
    result = assess_health(status)
    assert result["severity"] == "ok"
    assert result["show_banner"] is False


def test_assess_health_missing_required() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": False},
        ],
        "clamd_running": True,
    }
    result = assess_health(status)
    assert result["severity"] == "critical"
    assert any(i["code"] == "missing_required_packs" for i in result["issues"])


def test_assess_health_stale_signatures() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
        ],
        "signature_age_hours": 72,
        "clamd_running": True,
    }
    result = assess_health(status)
    assert result["severity"] == "high"
    assert any(i["code"] == "stale_signatures" for i in result["issues"])


def test_assess_health_clamonacc_prevention_unmanaged() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
        ],
        "clamd_running": True,
        "signature_age_hours": 1,
        "clamonacc_prevention_requested": True,
        "clamonacc_prevention_enforced": False,
    }
    result = assess_health(status)
    assert any(i["code"] == "clamonacc_prevention_unmanaged" for i in result["issues"])


def test_assess_health_fangfrisch_no_providers() -> None:
    status = {
        "packs": [
            {"name": "clamav", "tier": PackTier.REQUIRED.value, "installed": True},
            {"name": "fangfrisch", "tier": PackTier.OPTIONAL.value, "installed": True},
        ],
        "clamd_running": True,
        "signature_age_hours": 1,
        "fangfrisch_providers": [],
    }
    result = assess_health(status)
    assert any(i["code"] == "fangfrisch_no_providers" for i in result["issues"])
