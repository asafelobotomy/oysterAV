"""Scope constants for passwordless service-lifecycle grants."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

# ClamAV + maldet only (not fail2ban / firewalld).
PASSWORDLESS_SYSTEMCTL_UNITS = frozenset(
    {
        "clamav-daemon",
        "clamd@scan",
        "maldet",
        "clamav-freshclam.timer",
        "clamav-freshclam-once.timer",
        "clamav-freshclam",
        "clamav-clamonacc",
    },
)

PASSWORDLESS_SYSTEMCTL_ACTIONS = frozenset(
    {"enable", "start", "restart", "enable-now"},
)

GRANT_TTL = timedelta(days=7)
GRANT_STAMP_VERSION = 10

SERVICE_LIFECYCLE_ACTION_IDS = (
    "io.github.asafelobotomy.helper.systemctl-up",
    "io.github.asafelobotomy.helper.maldet-config",
)

EXPIRE_TIMER_UNIT = "oysterav-auth-grant-expire.timer"
EXPIRE_SERVICE_UNIT = "oysterav-auth-grant-expire.service"
EXPIRE_SCRIPT_PATH = "/usr/lib/oysterav/oyst-auth-expire"


def is_passwordless_systemctl(action: str, unit: str) -> bool:
    return (
        action.strip() in PASSWORDLESS_SYSTEMCTL_ACTIONS
        and unit.strip() in PASSWORDLESS_SYSTEMCTL_UNITS
    )


def grant_expires_at(*, now: datetime | None = None) -> datetime:
    base = now or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    return base + GRANT_TTL


def format_expires(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def parse_expires(value: str) -> datetime | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)
