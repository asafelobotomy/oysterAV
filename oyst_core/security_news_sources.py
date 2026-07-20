"""Security news source catalog and severity rules (no network I/O)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_SOURCE_IDS: tuple[str, ...] = ("arch", "ubuntu", "debian")

# CISA RSS retired May 2025 — do not add.
# Official / well-known open feeds only (fixed URLs; no user-supplied URLs).


@dataclass(frozen=True)
class NewsSource:
    id: str
    label: str
    url: str


NEWS_SOURCES: dict[str, NewsSource] = {
    "arch": NewsSource(
        "arch",
        "Arch",
        "https://security.archlinux.org/advisory/feed.atom",
    ),
    "ubuntu": NewsSource(
        "ubuntu",
        "Ubuntu",
        "https://ubuntu.com/security/notices/rss.xml",
    ),
    "debian": NewsSource(
        "debian",
        "Debian",
        "https://www.debian.org/security/dsa.rdf",
    ),
    "gentoo": NewsSource(
        "gentoo",
        "Gentoo",
        "https://security.gentoo.org/glsa/feed.rss",
    ),
    "fedora": NewsSource(
        "fedora",
        "Fedora",
        "https://bodhi.fedoraproject.org/rss/updates/?type=security",
    ),
    "oss-security": NewsSource(
        "oss-security",
        "oss-security",
        "https://seclists.org/rss/oss-sec.rss",
    ),
}

# Higher score wins. First matching tier applies (ordered critical → low).
SEVERITY_RULES: tuple[tuple[int, str, tuple[str, ...]], ...] = (
    (
        95,
        "critical",
        (
            "critical",
            "urgent",
            "remote code",
            "rce",
            "arbitrary code execution",
            "arbitrary code",
            "arbitrary command",
            "command execution",
            "privilege escalation",
            "code execution",
        ),
    ),
    (
        75,
        "high",
        (
            "important",
            "high",
            "unauthenticated",
            "remote ",
            " remotely",
        ),
    ),
    (
        45,
        "medium",
        (
            "moderate",
            "medium",
            "denial of service",
            " denial-of-service",
            " dos",
            "dos:",
            "vulnerability",
            "vulnerabilities",
            "multiple issues",
            "multiple vulnerabilities",
        ),
    ),
    (
        15,
        "low",
        (
            "low",
            "local ",
            "information disclosure",
            "information leak",
        ),
    ),
)


def normalize_source_ids(raw: Sequence[str] | None) -> list[str]:
    """Return valid unique source ids in catalog order; empty → defaults."""
    if not raw:
        return list(DEFAULT_SOURCE_IDS)
    seen: set[str] = set()
    ordered: list[str] = []
    for token in raw:
        sid = str(token).strip().lower()
        if sid not in NEWS_SOURCES or sid in seen:
            continue
        seen.add(sid)
        ordered.append(sid)
    if not ordered:
        return list(DEFAULT_SOURCE_IDS)
    # Preserve NEWS_SOURCES catalog order for stable cache fingerprints.
    return [sid for sid in NEWS_SOURCES if sid in seen]
