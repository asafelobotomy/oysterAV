"""Daily-cached security advisory headlines from selectable official feeds.

Re-export façade — implementations live in security_news_sources / parse / fetch.
"""

from __future__ import annotations

from oyst_core.security_news_fetch import (
    CACHE_MAX_AGE,
    FETCH_TIMEOUT_S,
    MAX_ITEMS,
    _merge_items,
    cache_dir,
    cache_path,
    fetch_security_news,
    headlines_for_ticker,
    list_security_news,
    relative_age_label,
    resolve_sources_from_config,
)
from oyst_core.security_news_parse import parse_feed_xml as _parse_feed_xml
from oyst_core.security_news_parse import score_severity
from oyst_core.security_news_sources import (
    DEFAULT_FEEDS,
    DEFAULT_SOURCE_IDS,
    NEWS_SOURCES,
    SEVERITY_RULES,
    NewsSource,
    normalize_source_ids,
)
from oyst_core.security_news_sources import SEVERITY_RULES as _SEVERITY_RULES

__all__ = [
    "CACHE_MAX_AGE",
    "DEFAULT_FEEDS",
    "DEFAULT_SOURCE_IDS",
    "FETCH_TIMEOUT_S",
    "MAX_ITEMS",
    "NEWS_SOURCES",
    "SEVERITY_RULES",
    "NewsSource",
    "_SEVERITY_RULES",
    "_merge_items",
    "_parse_feed_xml",
    "cache_dir",
    "cache_path",
    "fetch_security_news",
    "headlines_for_ticker",
    "list_security_news",
    "normalize_source_ids",
    "relative_age_label",
    "resolve_sources_from_config",
    "score_severity",
]
