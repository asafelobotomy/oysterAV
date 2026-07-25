"""Pure helpers for Dashboard posture cards (no GTK)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from oyst_core.health import SIGNATURE_STALE_HOURS

_MISCONFIGURED = frozenset(
    {
        "impossible",
        "block_misconfigured",
        "handoff_required",
    },
)


@dataclass(frozen=True)
class DashboardNav:
    """Where a card tap should go (or a special action)."""

    tab: str
    section: str | None = None
    job_id: str | None = None
    action: str | None = None  # e.g. ensure_clamd


@dataclass(frozen=True)
class DashboardCardModel:
    id: str
    title: str
    value: str
    description: str
    css_class: str = ""
    nav: DashboardNav | None = None


def _parse_iso(ts: str | datetime | None) -> datetime | None:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    text = str(ts).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_dashboard_relative_time(ts: str | datetime | None) -> str:
    dt = _parse_iso(ts)
    if dt is None:
        return "Never"
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    seconds = int((now - dt).total_seconds())
    if seconds < 0 or seconds < 60:
        return "Just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    days = hours // 24
    if days < 30:
        return f"{days}d ago"
    return dt.strftime("%Y-%m-%d")


def format_definitions_age(hours: float | None) -> tuple[str, str]:
    """Primary label + css for Definitions card."""
    if hours is None:
        return "Unknown", "warning"
    if hours < 24:
        return "Fresh", "success"
    if hours < SIGNATURE_STALE_HOURS:
        return f"{int(hours)}h old", "success"
    return "Stale", "warning"


def protection_card(status: dict[str, Any]) -> DashboardCardModel:
    running = bool(status.get("clamd_running"))
    if running:
        return DashboardCardModel(
            id="protection",
            title="Protection",
            value="Running",
            description="On-demand scanning engine",
            css_class="success",
            nav=DashboardNav(tab="settings", section="realtime"),
        )
    return DashboardCardModel(
        id="protection",
        title="Protection",
        value="Stopped",
        description="Tap to start clamd",
        css_class="warning",
        nav=DashboardNav(tab="settings", section="realtime", action="ensure_clamd"),
    )


def definitions_card(status: dict[str, Any]) -> DashboardCardModel:
    value, css = format_definitions_age(
        status.get("signature_age_hours")
        if isinstance(status.get("signature_age_hours"), (int, float))
        else None,
    )
    desc = "ClamAV definitions"
    providers = status.get("fangfrisch_providers")
    if isinstance(providers, list) and not providers:
        fangfrisch = next(
            (
                p
                for p in (status.get("packs") or [])
                if isinstance(p, dict) and p.get("name") == "fangfrisch" and p.get("installed")
            ),
            None,
        )
        if fangfrisch is not None:
            desc = "ClamAV definitions — Fangfrisch: no providers"
            if css == "success":
                css = "warning"
    return DashboardCardModel(
        id="definitions",
        title="Definitions",
        value=value,
        description=desc,
        css_class=css,
        nav=DashboardNav(tab="settings", section="maintenance"),
    )


def realtime_card(status: dict[str, Any], services: dict[str, Any]) -> DashboardCardModel:
    onaccess = status.get("clamonacc_onaccess")
    classification = ""
    include_paths: list[Any] = []
    if isinstance(onaccess, dict):
        classification = str(onaccess.get("classification") or "")
        raw_paths = onaccess.get("include_paths")
        if isinstance(raw_paths, list):
            include_paths = raw_paths

    svc = (services.get("services") or {}) if isinstance(services, dict) else {}
    clamonacc = svc.get("clamonacc") if isinstance(svc, dict) else None
    running = bool(clamonacc.get("running")) if isinstance(clamonacc, dict) else False
    if not running and isinstance(onaccess, dict):
        # Fallback when services payload omitted; pack details sometimes embed running.
        pass

    prevention_requested = bool(status.get("clamonacc_prevention_requested"))
    prevention_enforced = bool(status.get("clamonacc_prevention_enforced"))

    nav = DashboardNav(tab="settings", section="realtime")
    if classification in _MISCONFIGURED or (
        prevention_requested and not prevention_enforced and classification != "blocking"
    ):
        reason = {
            "impossible": "Kernel cannot block on access",
            "block_misconfigured": "Host OnAccessPrevention misconfigured",
            "handoff_required": "Host clamd.conf not readable",
        }.get(classification, "Prevention requested but not enforced")
        return DashboardCardModel(
            id="realtime",
            title="Real-time",
            value="Misconfigured",
            description=reason,
            css_class="error",
            nav=nav,
        )
    if running:
        n = len(include_paths)
        paths = f"{n} watched path" if n == 1 else f"{n} watched paths"
        return DashboardCardModel(
            id="realtime",
            title="Real-time",
            value="Watching",
            description=paths if n else "On-access monitor running",
            css_class="success",
            nav=nav,
        )
    return DashboardCardModel(
        id="realtime",
        title="Real-time",
        value="Off",
        description="On-access monitor not running",
        css_class="warning",
        nav=nav,
    )


def last_scan_card(
    status: dict[str, Any],
    history: list[dict[str, Any]],
) -> DashboardCardModel:
    latest = history[0] if history else None
    started = None
    if isinstance(latest, dict):
        started = latest.get("started_at") or latest.get("finished_at")
    if started is None:
        started = status.get("last_scan_at")
    stamp = started if isinstance(started, (str, datetime)) else None
    primary = format_dashboard_relative_time(stamp)

    if not isinstance(latest, dict) and primary == "Never":
        return DashboardCardModel(
            id="last_scan",
            title="Last scan",
            value="Never",
            description="Never scanned",
            css_class="",
            nav=DashboardNav(tab="scan"),
        )

    state = str((latest or {}).get("state") or "completed") if latest else "completed"
    clean = bool((latest or {}).get("clean", True)) if latest else True
    findings = int((latest or {}).get("findings_count") or 0) if latest else 0
    job_id = str((latest or {}).get("job_id") or "") if latest else ""

    if state == "cancelled":
        return DashboardCardModel(
            id="last_scan",
            title="Last scan",
            value=primary,
            description="Cancelled",
            css_class="warning",
            nav=DashboardNav(tab="reports", job_id=job_id or None)
            if job_id
            else DashboardNav(tab="scan"),
        )
    if not clean or findings > 0:
        n = findings or 1
        label = "1 threat" if n == 1 else f"{n} threats"
        return DashboardCardModel(
            id="last_scan",
            title="Last scan",
            value=primary,
            description=label,
            css_class="error",
            nav=DashboardNav(tab="reports", job_id=job_id or None)
            if job_id
            else DashboardNav(tab="scan"),
        )
    if latest and latest.get("has_errors"):
        return DashboardCardModel(
            id="last_scan",
            title="Last scan",
            value=primary,
            description="Completed with errors",
            css_class="warning",
            nav=DashboardNav(tab="reports", job_id=job_id or None)
            if job_id
            else DashboardNav(tab="scan"),
        )
    return DashboardCardModel(
        id="last_scan",
        title="Last scan",
        value=primary,
        description="Clean",
        css_class="success",
        nav=DashboardNav(tab="scan"),
    )


def quarantine_card(count: int) -> DashboardCardModel:
    return DashboardCardModel(
        id="quarantine",
        title="Quarantine",
        value=str(count),
        description="item in vault" if count == 1 else "items in vault",
        css_class="error" if count else "success",
        nav=DashboardNav(tab="quarantine"),
    )


def host_shield_card(firewall: dict[str, Any], services: dict[str, Any]) -> DashboardCardModel:
    ufw_on = bool(firewall.get("ufw_active"))
    fwd_on = bool(firewall.get("firewalld_active"))
    active = str(firewall.get("active") or "none")
    if ufw_on or fwd_on:
        fw_value = "On"
        fw_css = "success"
        backend = "ufw" if ufw_on else "firewalld"
    elif active == "none":
        fw_value = "Off"
        fw_css = "warning"
        backend = "No host firewall enabled"
    elif active == "nft-direct":
        fw_value = "On"
        fw_css = "success"
        backend = "nftables"
    else:
        fw_value = "Unknown"
        fw_css = "warning"
        backend = "Firewall status unclear"

    svc = (services.get("services") or {}) if isinstance(services, dict) else {}
    fail2ban = svc.get("fail2ban") if isinstance(svc, dict) else None
    if isinstance(fail2ban, dict):
        if fail2ban.get("running"):
            ban = "fail2ban active"
        elif fail2ban.get("unit"):
            ban = "fail2ban installed, not running"
            if fw_css == "success":
                fw_css = "warning"
        else:
            ban = "fail2ban not installed"
    else:
        ban = "fail2ban status unknown"

    if ufw_on or fwd_on or active == "nft-direct":
        desc = f"{backend} · {ban}"
    else:
        desc = ban if active == "none" else f"{backend} · {ban}"

    return DashboardCardModel(
        id="host_shield",
        title="Host shield",
        value=fw_value,
        description=desc,
        css_class=fw_css,
        nav=DashboardNav(tab="shield"),
    )


def helper_card(auth: dict[str, Any]) -> DashboardCardModel | None:
    helper = auth.get("helper") if isinstance(auth, dict) else None
    if not isinstance(helper, dict):
        return None
    installed = bool(helper.get("installed"))
    current = bool(helper.get("policy_current", True))
    if installed and current:
        return None
    if installed and not current:
        ver = helper.get("policy_version", "?")
        return DashboardCardModel(
            id="helper",
            title="Helper",
            value="Needs update",
            description=f"Policy outdated (v{ver})",
            css_class="warning",
            nav=DashboardNav(tab="settings", section="services"),
        )
    return DashboardCardModel(
        id="helper",
        title="Helper",
        value="Not installed",
        description="Privileged actions will fail",
        css_class="warning",
        nav=DashboardNav(tab="settings", section="services"),
    )


def build_dashboard_cards(
    *,
    status: dict[str, Any],
    history: list[dict[str, Any]],
    quarantine_count: int,
    services: dict[str, Any],
    firewall: dict[str, Any],
    auth: dict[str, Any],
) -> list[DashboardCardModel]:
    """Build the fixed posture grid plus optional Helper card."""
    cards = [
        protection_card(status),
        definitions_card(status),
        realtime_card(status, services),
        last_scan_card(status, history),
        quarantine_card(quarantine_count),
        host_shield_card(firewall, services),
    ]
    helper = helper_card(auth)
    if helper is not None:
        cards.append(helper)
    return cards
