"""System health assessment for CLI and future GUI mapping."""

from __future__ import annotations

from typing import Any, Literal

from oyst_core.models import PackTier

SIGNATURE_STALE_HOURS = 48

HealthSeverity = Literal["ok", "info", "medium", "high", "critical"]


def _issue(
    code: str,
    severity: HealthSeverity,
    title: str,
    detail: str,
    action: str,
) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommended_action": action,
    }


def assess_health(status: dict[str, Any]) -> dict[str, Any]:
    """Evaluate aggregate status and return structured health assessment."""
    issues: list[dict[str, str]] = []
    packs = status.get("packs", [])

    missing_required = [
        p for p in packs if p.get("tier") == PackTier.REQUIRED.value and not p.get("installed")
    ]
    if missing_required:
        names = ", ".join(str(p.get("name", "?")) for p in missing_required)
        issues.append(
            _issue(
                "missing_required_packs",
                "critical",
                "Required security packs missing",
                f"Missing: {names}",
                "Run: oyst-cli setup run --skip-schedule or oyst-cli packs install <name>",
            ),
        )

    sig_hours = status.get("signature_age_hours")
    if isinstance(sig_hours, (int, float)) and sig_hours > SIGNATURE_STALE_HOURS:
        issues.append(
            _issue(
                "stale_signatures",
                "high",
                "Virus signatures are stale",
                f"Last update was {int(sig_hours)} hours ago.",
                "Run: oyst-cli runtime bootstrap --skip-install or oyst-cli freshclam update",
            ),
        )

    if not status.get("clamd_running", False):
        issues.append(
            _issue(
                "clamd_down",
                "medium",
                "ClamAV daemon is not running",
                "On-demand scans fall back to slower clamscan until clamd is started "
                "(scan.backend=auto).",
                "Run: oyst-cli clamav clamd ensure",
            ),
        )

    if status.get("clamonacc_prevention_requested") and not status.get(
        "clamonacc_prevention_enforced",
        False,
    ):
        onaccess = status.get("clamonacc_onaccess")
        classification = ""
        if isinstance(onaccess, dict):
            classification = str(onaccess.get("classification") or "")
        if classification == "impossible":
            issues.append(
                _issue(
                    "clamonacc_prevention_impossible",
                    "medium",
                    "On-access prevention not possible on this kernel",
                    "Kernel lacks CONFIG_FANOTIFY_ACCESS_PERMISSIONS; blocking cannot work.",
                    "Set clamonacc.prevention false, or use a kernel with "
                    "fanotify access permissions",
                ),
            )
        elif classification == "block_misconfigured":
            issues.append(
                _issue(
                    "clamonacc_prevention_misconfigured",
                    "medium",
                    "On-access prevention is misconfigured on the host",
                    "OnAccessPrevention is set but OnAccessMountPath is also present "
                    "(incompatible). Use OnAccessIncludePath only.",
                    "See docs/user-guide/clamonacc-prevention.md",
                ),
            )
        elif classification == "handoff_required":
            issues.append(
                _issue(
                    "clamonacc_prevention_unmanaged",
                    "medium",
                    "On-access prevention is requested but host conf was not readable",
                    "clamonacc.prevention=true but no readable clamd.conf was found to verify "
                    "OnAccessPrevention.",
                    "Install/configure host ClamAV, or set clamonacc.prevention false",
                ),
            )
        else:
            issues.append(
                _issue(
                    "clamonacc_prevention_unmanaged",
                    "medium",
                    "On-access prevention is requested but not enabled on the host",
                    "clamonacc.prevention=true requires OnAccessPrevention yes in host "
                    "clamd.conf; process-mode clamonacc remains detect-only with --fdpass.",
                    "Set OnAccessPrevention yes in clamd.conf "
                    "(docs/user-guide/clamonacc-prevention.md), or set "
                    "clamonacc.prevention false",
                ),
            )

    fangfrisch = next((p for p in packs if p.get("name") == "fangfrisch"), None)
    if fangfrisch and fangfrisch.get("installed"):
        providers = status.get("fangfrisch_providers")
        if isinstance(providers, list) and not providers:
            issues.append(
                _issue(
                    "fangfrisch_no_providers",
                    "info",
                    "Fangfrisch has no providers enabled",
                    "Unofficial ClamAV databases will not refresh until providers are set.",
                    "Run: oyst-cli config set fangfrisch.providers sanesecurity,urlhaus",
                ),
            )

    active_job = status.get("active_job")
    if active_job:
        issues.append(
            _issue(
                "active_job",
                "info",
                "Scan in progress",
                f"Job {active_job} is running.",
                "Wait for the scan to finish or check: oyst-cli history --json",
            ),
        )

    severity_order: tuple[HealthSeverity, ...] = (
        "critical",
        "high",
        "medium",
        "info",
        "ok",
    )
    overall: HealthSeverity = "ok"
    for level in severity_order:
        if any(i["severity"] == level for i in issues):
            overall = level
            break

    show_banner = overall in ("critical", "high", "medium", "info")
    if overall == "ok":
        banner_title = "System protected"
        banner_body = "All required packs are installed."
    else:
        banner_title = issues[0]["title"]
        banner_body = issues[0]["detail"]

    recommended_actions = [i["recommended_action"] for i in issues if i["recommended_action"]]

    return {
        "severity": overall,
        "show_banner": show_banner,
        "banner_title": banner_title,
        "banner_body": banner_body,
        "issues": issues,
        "recommended_actions": recommended_actions,
    }
