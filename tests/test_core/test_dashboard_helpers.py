"""Pure Dashboard posture card helpers."""

from __future__ import annotations

from oysterav.gui.dashboard_helpers import (
    build_dashboard_cards,
    definitions_card,
    format_definitions_age,
    helper_card,
    host_shield_card,
    last_scan_card,
    protection_card,
    realtime_card,
)


def test_format_definitions_age() -> None:
    assert format_definitions_age(None) == ("Unknown", "warning")
    assert format_definitions_age(3.0) == ("Fresh", "success")
    assert format_definitions_age(30.0)[0].endswith("h old")
    assert format_definitions_age(100.0) == ("Stale", "warning")


def test_protection_card_running_and_stopped() -> None:
    running = protection_card({"clamd_running": True})
    assert running.value == "Running"
    assert running.nav is not None
    assert running.nav.action is None
    stopped = protection_card({"clamd_running": False})
    assert stopped.value == "Stopped"
    assert stopped.nav is not None
    assert stopped.nav.action == "ensure_clamd"


def test_definitions_fangfrisch_empty_providers() -> None:
    status = {
        "signature_age_hours": 5.0,
        "fangfrisch_providers": [],
        "packs": [{"name": "fangfrisch", "installed": True}],
    }
    card = definitions_card(status)
    assert "Fangfrisch" in card.description
    assert card.css_class == "warning"


def test_realtime_watching_off_misconfigured() -> None:
    watching = realtime_card(
        {
            "clamonacc_onaccess": {
                "classification": "blocking",
                "include_paths": ["/home/a/Downloads"],
            },
            "clamonacc_prevention_requested": True,
            "clamonacc_prevention_enforced": True,
        },
        {"services": {"clamonacc": {"running": True}}},
    )
    assert watching.value == "Watching"
    assert "1 watched path" in watching.description

    off = realtime_card(
        {
            "clamonacc_onaccess": {"classification": "blocking", "include_paths": []},
            "clamonacc_prevention_requested": False,
            "clamonacc_prevention_enforced": False,
        },
        {"services": {"clamonacc": {"running": False}}},
    )
    assert off.value == "Off"

    bad = realtime_card(
        {
            "clamonacc_onaccess": {"classification": "block_misconfigured"},
            "clamonacc_prevention_requested": True,
            "clamonacc_prevention_enforced": False,
        },
        {"services": {"clamonacc": {"running": False}}},
    )
    assert bad.value == "Misconfigured"
    assert bad.css_class == "error"


def test_last_scan_threats_and_never() -> None:
    never = last_scan_card({}, [])
    assert never.value == "Never"
    assert never.nav is not None
    assert never.nav.tab == "scan"

    threats = last_scan_card(
        {},
        [
            {
                "started_at": "2026-07-24T10:00:00",
                "clean": False,
                "findings_count": 2,
                "job_id": "abc",
                "state": "completed",
            }
        ],
    )
    assert threats.description == "2 threats"
    assert threats.css_class == "error"
    assert threats.nav is not None
    assert threats.nav.tab == "reports"
    assert threats.nav.job_id == "abc"


def test_host_shield_and_helper_visibility() -> None:
    host = host_shield_card(
        {"ufw_active": True, "firewalld_active": False, "active": "ufw"},
        {"services": {"fail2ban": {"running": True, "unit": "fail2ban"}}},
    )
    assert host.value == "On"
    assert "fail2ban on" in host.description

    # Firewall off + fail2ban on must not read as plain Off (Shield says on).
    partial = host_shield_card(
        {"ufw_active": False, "firewalld_active": False, "active": "none"},
        {"services": {"fail2ban": {"running": True, "unit": "fail2ban"}}},
    )
    assert partial.value == "Partial"
    assert "fail2ban on" in partial.description
    assert "firewall off" in partial.description

    both_off = host_shield_card(
        {"ufw_active": False, "firewalld_active": False, "active": "none"},
        {"services": {"fail2ban": {"running": False, "unit": "fail2ban"}}},
    )
    assert both_off.value == "Off"

    nft = host_shield_card(
        {"ufw_active": False, "firewalld_active": False, "active": "nft-direct"},
        {"services": {"fail2ban": {"running": False, "unit": ""}}},
    )
    assert nft.value == "Partial"
    assert "managed off" in nft.description

    assert helper_card({"helper": {"installed": True, "policy_current": True}}) is None
    stale = helper_card(
        {"helper": {"installed": True, "policy_current": False, "policy_version": 11}},
    )
    assert stale is not None
    assert stale.value == "Needs update"
    missing = helper_card({"helper": {"installed": False}})
    assert missing is not None
    assert missing.value == "Not installed"


def test_build_dashboard_cards_appends_helper_when_stale() -> None:
    cards = build_dashboard_cards(
        status={"clamd_running": True, "signature_age_hours": 2.0},
        history=[],
        quarantine_count=0,
        services={"services": {"clamonacc": {"running": False}, "fail2ban": {}}},
        firewall={"active": "none", "ufw_active": False, "firewalld_active": False},
        auth={"helper": {"installed": True, "policy_current": False, "policy_version": 11}},
    )
    assert len(cards) == 7
    assert cards[-1].id == "helper"
    assert [c.id for c in cards[:6]] == [
        "protection",
        "definitions",
        "realtime",
        "last_scan",
        "quarantine",
        "host_shield",
    ]
