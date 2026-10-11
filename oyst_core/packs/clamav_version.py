"""ClamAV security-patch advisory (non-blocking; the hard floor is ClamAVPack.min_version)."""

from __future__ import annotations

import re

from oyst_core.privileged.runner import version_gte

# Oldest patch release per supported line with current security fixes
# (1.5.4 / 1.4.6, 2026-08-07: clamd STATS crash, bundled UnRAR CVEs).
RECOMMENDED_PATCH: dict[tuple[int, int], str] = {(1, 4): "1.4.6", (1, 5): "1.5.4"}


def security_advisory(version: str | None) -> str | None:
    """Plain-language update advice when a supported line lacks security fixes."""
    if not version:
        return None
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        return None
    recommended = RECOMMENDED_PATCH.get((int(match.group(1)), int(match.group(2))))
    if recommended and not version_gte(version, recommended):
        return f"ClamAV {version} is missing security fixes; update to {recommended} or newer."
    return None
