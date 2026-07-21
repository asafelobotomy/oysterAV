"""Priority ordering for privilege concert / bulk install-update plans."""

from __future__ import annotations

from oyst_core.models import PackTier

# High → low: used for Install All, Update all, harden, Auto-Install disclosure.
PRIORITY_REQUIRED = 10
PRIORITY_RECOMMENDED = 20
PRIORITY_OPTIONAL = 30
PRIORITY_HARDEN = 40
PRIORITY_PROPUPD = 50

_PACK_PRIORITY: dict[str, int] = {
    "clamav": PRIORITY_REQUIRED,
    "freshclam": PRIORITY_REQUIRED,
    "clamonacc": PRIORITY_REQUIRED,
    "rkhunter": PRIORITY_RECOMMENDED,
    "chkrootkit": PRIORITY_RECOMMENDED,
    "unhide": PRIORITY_RECOMMENDED,
    "lynis": PRIORITY_OPTIONAL,
    "fangfrisch": PRIORITY_OPTIONAL,
    "maldet": PRIORITY_OPTIONAL,
    "firewall": PRIORITY_OPTIONAL,
    "fail2ban": PRIORITY_OPTIONAL,
}

_TIER_PRIORITY: dict[str, int] = {
    PackTier.REQUIRED.value: PRIORITY_REQUIRED,
    PackTier.RECOMMENDED.value: PRIORITY_RECOMMENDED,
    PackTier.OPTIONAL.value: PRIORITY_OPTIONAL,
}

_HARDEN_ORDER: tuple[str, ...] = (
    "harden-clamd",
    "harden-fdpass",
    "harden-virusevent",
    "harden-disable-cache",
    "harden-rkhunter-defaults",
    "firewall-ensure",
)

_UPDATE_STEP_ORDER: tuple[str, ...] = (
    "packages",
    "freshclam",
    "runtime-signatures",
    "fangfrisch",
    "rkhunter-update",
    "maldet-sigs",
    "rkhunter-propupd",
)


def pack_priority(name: str, *, tier: str | None = None) -> int:
    """Sort key for a pack name (lower = earlier)."""
    if name in _PACK_PRIORITY:
        return _PACK_PRIORITY[name]
    if tier and tier in _TIER_PRIORITY:
        return _TIER_PRIORITY[tier]
    return PRIORITY_OPTIONAL


def sort_pack_names(names: list[str], *, tiers: dict[str, str] | None = None) -> list[str]:
    """Stable priority sort for pack install lists."""
    tiers = tiers or {}

    def key(n: str) -> tuple[int, str]:
        return (pack_priority(n, tier=tiers.get(n)), n)

    return sorted(names, key=key)


def harden_step_priority(step_id: str) -> int:
    try:
        return PRIORITY_HARDEN + _HARDEN_ORDER.index(step_id)
    except ValueError:
        return PRIORITY_HARDEN + 90


def update_step_priority(step_id: str) -> int:
    if step_id == "rkhunter-propupd":
        return PRIORITY_PROPUPD
    try:
        return 15 + _UPDATE_STEP_ORDER.index(step_id)
    except ValueError:
        return 80


def sort_by_priority(
    items: list[tuple[int, str]],
) -> list[str]:
    """Sort (priority, id) pairs; return ids in order."""
    return [i for _, i in sorted(items, key=lambda t: (t[0], t[1]))]


__all__ = [
    "PRIORITY_HARDEN",
    "PRIORITY_OPTIONAL",
    "PRIORITY_PROPUPD",
    "PRIORITY_RECOMMENDED",
    "PRIORITY_REQUIRED",
    "harden_step_priority",
    "pack_priority",
    "sort_by_priority",
    "sort_pack_names",
    "update_step_priority",
]
