"""Daily-cached security advisory headlines from selectable official feeds."""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

_logger = logging.getLogger("oyst.security_news")

CACHE_MAX_AGE = timedelta(hours=24)
MAX_ITEMS = 30
FETCH_TIMEOUT_S = 20
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

# Backward-compatible alias: (label, url) for older tests/imports.
DEFAULT_FEEDS: tuple[tuple[str, str], ...] = tuple(
    (NEWS_SOURCES[sid].label, NEWS_SOURCES[sid].url) for sid in DEFAULT_SOURCE_IDS
)

_NVR_TITLE_RE = re.compile(
    r"^[a-zA-Z0-9._+-]+-[0-9][a-zA-Z0-9._+-]*-[0-9][a-zA-Z0-9._+]*$",
)

# Higher score wins. First matching tier applies (ordered critical → low).
_SEVERITY_RULES: tuple[tuple[int, str, tuple[str, ...]], ...] = (
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


def cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    path = base / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_path() -> Path:
    return cache_dir() / "security_news.json"


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


def resolve_sources_from_config() -> list[str]:
    from oyst_core.config import load_config

    return normalize_source_ids(load_config().ui.security_news_sources)


def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _child_text(parent: ET.Element, names: set[str]) -> str:
    for child in parent:
        if _local_tag(child.tag) in names:
            text = (child.text or "").strip()
            if text:
                return text
            # Atom link may be empty with href=
            href = child.attrib.get("href")
            if href:
                return href.strip()
            # content:encoded / description may nest HTML text in descendants
            joined = "".join(child.itertext()).strip()
            if joined:
                return joined
    return ""


def _child_link(parent: ET.Element) -> str:
    for child in parent:
        if _local_tag(child.tag) != "link":
            continue
        href = child.attrib.get("href")
        if href:
            return href.strip()
        text = (child.text or "").strip()
        if text:
            return text
    # RDF / RSS 1.0 often uses rdf:about on the item
    about = parent.attrib.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about")
    if about:
        return about.strip()
    about = parent.attrib.get("about")
    if about:
        return about.strip()
    return ""


def _parse_datetime(raw: str) -> datetime | None:
    text = raw.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt
    except (TypeError, ValueError, IndexError):
        return None


def _entry_published(entry: ET.Element) -> str:
    for name in ("published", "updated", "pubDate", "date"):
        value = _child_text(entry, {name})
        if value:
            return value
    return ""


def _entry_description(entry: ET.Element) -> str:
    raw = _child_text(entry, {"description", "summary", "content", "encoded"})
    if not raw:
        return ""
    # Strip coarse HTML tags for scoring / Fedora title repair.
    text = re.sub(r"<[^>]+>", " ", raw)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def score_severity(title: str, description: str = "") -> tuple[int, str]:
    """Heuristic severity from title + description. Returns (score, label)."""
    blob = f"{title} {description}".lower()
    for score, label, needles in _SEVERITY_RULES:
        for needle in needles:
            if needle in blob:
                return score, label
    return 0, "unknown"


def _enrich_title(title: str, description: str) -> str:
    """Replace bare NVR package titles with a short description lead-in."""
    if not description or not _NVR_TITLE_RE.match(title.strip()):
        return title
    lead = description.strip()
    if len(lead) > 80:
        lead = lead[:77].rstrip() + "…"
    return lead or title


def _parse_feed_xml(source: str, xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    items: list[dict[str, Any]] = []
    root_name = _local_tag(root.tag)

    entries: list[ET.Element] = []
    if root_name == "feed":
        entries = [el for el in root if _local_tag(el.tag) == "entry"]
    elif root_name in ("rss", "RDF"):
        # RSS 2.0: rss/channel/item ; RSS 1.0: RDF/item
        for el in root.iter():
            if _local_tag(el.tag) == "item":
                entries.append(el)
    else:
        for el in root.iter():
            if _local_tag(el.tag) in ("entry", "item"):
                entries.append(el)

    for entry in entries:
        title = _child_text(entry, {"title"})
        if not title:
            continue
        link = _child_link(entry)
        published = _entry_published(entry)
        description = _entry_description(entry)
        display_title = _enrich_title(title, description)
        severity, severity_label = score_severity(display_title, description)
        items.append(
            {
                "source": source,
                "title": display_title,
                "link": link,
                "published": published,
                "severity": severity,
                "severity_label": severity_label,
            },
        )
    return items


def _fetch_url(url: str) -> str:
    req = Request(
        url,
        headers={"User-Agent": "oysterAV/security-news (+https://github.com/asafelobotomy/oysterAV)"},
    )
    with urlopen(req, timeout=FETCH_TIMEOUT_S) as response:  # noqa: S310 — fixed official URLs
        raw = response.read()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)


def _load_cache() -> dict[str, Any] | None:
    path = cache_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _save_cache(payload: dict[str, Any]) -> None:
    path = cache_path()
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _cache_age(payload: dict[str, Any]) -> timedelta | None:
    raw = payload.get("fetched_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        fetched = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=UTC)
    return datetime.now(UTC) - fetched


def _is_fresh(payload: dict[str, Any], sources: list[str]) -> bool:
    age = _cache_age(payload)
    if age is None or age > CACHE_MAX_AGE:
        return False
    cached_sources = payload.get("sources")
    if not isinstance(cached_sources, list):
        return False
    return [str(s) for s in cached_sources] == sources


def _item_published_dt(item: dict[str, Any]) -> datetime:
    dt = _parse_datetime(str(item.get("published") or ""))
    if dt is None:
        return datetime.min.replace(tzinfo=UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _merge_items(batches: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for batch in batches:
        for item in batch:
            key = str(item.get("link") or f"{item.get('source')}:{item.get('title')}")
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)

    def sort_key(item: dict[str, Any]) -> tuple[int, datetime]:
        severity = int(item.get("severity") or 0)
        return (severity, _item_published_dt(item))

    merged.sort(key=sort_key, reverse=True)
    return merged[:MAX_ITEMS]


def fetch_security_news(
    *,
    force: bool = False,
    sources: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return cached or freshly fetched advisory headlines for selected sources."""
    if sources is not None:
        selected = normalize_source_ids(sources)
    else:
        selected = normalize_source_ids(resolve_sources_from_config())
    cached = _load_cache()
    if cached is not None and not force and _is_fresh(cached, selected):
        result = dict(cached)
        result["stale"] = False
        result["from_cache"] = True
        return result

    batches: list[list[dict[str, Any]]] = []
    errors: list[dict[str, str]] = []
    for sid in selected:
        src = NEWS_SOURCES[sid]
        try:
            xml_text = _fetch_url(src.url)
            batches.append(_parse_feed_xml(src.label, xml_text))
        except (OSError, URLError, ET.ParseError, TimeoutError, ValueError) as exc:
            _logger.warning("security news fetch failed for %s: %s", src.label, exc)
            errors.append({"source": src.label, "error": str(exc)})

    items = _merge_items(batches)
    if not items and cached is not None:
        result = dict(cached)
        result["stale"] = True
        result["from_cache"] = True
        result["errors"] = errors
        return result

    payload: dict[str, Any] = {
        "fetched_at": datetime.now(UTC).isoformat(),
        "sources": selected,
        "items": items,
        "errors": errors,
        "stale": False,
        "from_cache": False,
    }
    try:
        _save_cache(payload)
    except OSError as exc:
        _logger.warning("could not write security news cache: %s", exc)
    return payload


def list_security_news(
    *,
    force_refresh: bool = False,
    sources: Sequence[str] | None = None,
) -> dict[str, Any]:
    return fetch_security_news(force=force_refresh, sources=sources)


def relative_age_label(published: str, *, now: datetime | None = None) -> str:
    """Compact age for ticker: (today), (2d), (1w), (3w), (2mo)."""
    dt = _parse_datetime(published)
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    ref = now if now is not None else datetime.now(UTC)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=UTC)
    delta = ref - dt
    days = delta.days
    if days < 0:
        days = 0
    if days == 0:
        return "(today)"
    if days == 1:
        return "(1d)"
    if days < 7:
        return f"({days}d)"
    weeks = days // 7
    if weeks < 5:
        return f"({weeks}w)"
    months = max(1, days // 30)
    return f"({months}mo)"


def headlines_for_ticker(payload: dict[str, Any] | None = None) -> str:
    """Single-line ticker text from a news payload."""
    data = payload if payload is not None else list_security_news()
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items:
        return ""
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source") or "").strip()
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        age = relative_age_label(str(item.get("published") or ""))
        base = f"{source} · {title}" if source else title
        if age:
            base = f"{base} {age}"
        parts.append(base)
    return "   ···   ".join(parts)
