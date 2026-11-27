"""Integrity pins trusted by the root helper.

The helper must never trust a digest supplied on argv: the caller is
unprivileged and can hash whatever file it likes. Digests live here, in the
root-owned install prefix, and callers' values are only accepted when they
match a pin.
"""

from __future__ import annotations

# maldet-<MALDET_VERSION>.tar.gz (rfxn GitHub release). Update via PR after reviewing a new
# upstream release.
MALDET_SHA256 = "26674c72208a4c32ae4ed8770a2b5c036b35c0894a4812450df11c5a53d7d8e5"

PINNED_MALDET_SHA256 = frozenset({MALDET_SHA256})


def require_pinned_maldet_sha256(value: str) -> str:
    """Return the pinned digest if ``value`` matches one; else raise ValueError."""
    digest = (value or "").strip().lower()
    if digest not in PINNED_MALDET_SHA256:
        raise ValueError("maldet tarball sha256 is not pinned by the privileged helper")
    return digest


__all__ = ["MALDET_SHA256", "PINNED_MALDET_SHA256", "require_pinned_maldet_sha256"]
