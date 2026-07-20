"""Security news cache I/O, fetch, and ticker helpers."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

from oyst_core.security_news_parse import parse_datetime, parse_feed_xml
from oyst_core.security_news_sources import NEWS_SOURCES, normalize_source_ids

_logger = logging.getLogger("oyst.security_news")

CACHE_MAX_AGE = timedelta(hours=24)
MAX_ITEMS = 30
FETCH_TIMEOUT_S = 20


def cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    path = base / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_path() -> Path:
    return cache_dir() / "security_news.json"


def resolve_sources_from_config() -> list[str]:
    from oyst_core.config import load_config

    return normalize_source_ids(load_config().ui.security_news_sources)


def _fetch_url(url: str) -> str:
    req = Request(
        url,
        headers={
            "User-Agent": "oysterAV/security-news (+https://github.com/asafelobotomy/oysterAV)"
        },
    )
    with urlopen(req, timeout=FETCH_TIMEOUT_S) as response:  # noqa: S310 — fixed official URLs  # nosec B310
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
    dt = parse_datetime(str(item.get("published") or ""))
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
            batches.append(parse_feed_xml(src.label, xml_text))
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
    dt = parse_datetime(published)
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
