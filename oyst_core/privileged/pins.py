"""Integrity pins trusted by the root helper.

The helper must never trust a digest supplied on argv: the caller is
unprivileged and can hash whatever file it likes. Digests live here, in the
root-owned install prefix, and callers' values are only accepted when they
match a pin.
"""

from __future__ import annotations

# maldetect-<MALDET_VERSION>.tar.gz (rfxn). Update via PR after reviewing a new upstream release.
MALDET_SHA256 = "76f1d260dac5e0bb3ca487f8d3e119655196de87b08ec89dfd73155e083feb5d"

PINNED_MALDET_SHA256 = frozenset({MALDET_SHA256})


def require_pinned_maldet_sha256(value: str) -> str:
    """Return the pinned digest if ``value`` matches one; else raise ValueError."""
    digest = (value or "").strip().lower()
    if digest not in PINNED_MALDET_SHA256:
        raise ValueError("maldet tarball sha256 is not pinned by the privileged helper")
    return digest


__all__ = ["MALDET_SHA256", "PINNED_MALDET_SHA256", "require_pinned_maldet_sha256"]
