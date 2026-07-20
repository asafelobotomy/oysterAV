"""XML/Atom feed parsing and severity scoring for security news."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from xml.etree import ElementTree as ET

from oyst_core.security_news_sources import SEVERITY_RULES

_NVR_TITLE_RE = re.compile(
    r"^[a-zA-Z0-9._+-]+-[0-9][a-zA-Z0-9._+-]*-[0-9][a-zA-Z0-9._+]*$",
)


def local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _local_tag(tag: str) -> str:
    return local_tag(tag)


def child_text(parent: ET.Element, names: set[str]) -> str:
    for child in parent:
        if local_tag(child.tag) in names:
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


def child_link(parent: ET.Element) -> str:
    for child in parent:
        if local_tag(child.tag) != "link":
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


def parse_datetime(raw: str) -> datetime | None:
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


def entry_published(entry: ET.Element) -> str:
    for name in ("published", "updated", "pubDate", "date"):
        value = child_text(entry, {name})
        if value:
            return value
    return ""


def entry_description(entry: ET.Element) -> str:
    raw = child_text(entry, {"description", "summary", "content", "encoded"})
    if not raw:
        return ""
    # Strip coarse HTML tags for scoring / Fedora title repair.
    text = re.sub(r"<[^>]+>", " ", raw)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def score_severity(title: str, description: str = "") -> tuple[int, str]:
    """Heuristic severity from title + description. Returns (score, label)."""
    blob = f"{title} {description}".lower()
    for score, label, needles in SEVERITY_RULES:
        for needle in needles:
            if needle in blob:
                return score, label
    return 0, "unknown"


def enrich_title(title: str, description: str) -> str:
    """Replace bare NVR package titles with a short description lead-in."""
    if not description or not _NVR_TITLE_RE.match(title.strip()):
        return title
    lead = description.strip()
    if len(lead) > 80:
        lead = lead[:77].rstrip() + "…"
    return lead or title


def parse_feed_xml(source: str, xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    items: list[dict[str, Any]] = []
    root_name = local_tag(root.tag)

    entries: list[ET.Element] = []
    if root_name == "feed":
        entries = [el for el in root if local_tag(el.tag) == "entry"]
    elif root_name in ("rss", "RDF"):
        # RSS 2.0: rss/channel/item ; RSS 1.0: RDF/item
        for el in root.iter():
            if local_tag(el.tag) == "item":
                entries.append(el)
    else:
        for el in root.iter():
            if local_tag(el.tag) in ("entry", "item"):
                entries.append(el)

    for entry in entries:
        title = child_text(entry, {"title"})
        if not title:
            continue
        link = child_link(entry)
        published = entry_published(entry)
        description = entry_description(entry)
        display_title = enrich_title(title, description)
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


# Private aliases for façade / tests that may use underscored names
_child_text = child_text
_child_link = child_link
_parse_datetime = parse_datetime
_entry_published = entry_published
_entry_description = entry_description
_enrich_title = enrich_title
_parse_feed_xml = parse_feed_xml
