"""Unit tests for security news feed parsing, severity, and sources."""

from __future__ import annotations

from datetime import UTC, datetime

from oyst_core.security_news import (
    _merge_items,
    _parse_feed_xml,
    headlines_for_ticker,
    normalize_source_ids,
    relative_age_label,
    score_severity,
)

ATOM = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Arch Linux Security Advisories</title>
  <entry>
    <title>ASA-202607-1: openssl: arbitrary code execution</title>
    <link href="https://security.archlinux.org/ASA-202607-1"/>
    <updated>2026-07-10T12:00:00+00:00</updated>
  </entry>
</feed>
"""

RSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Ubuntu Security Notices</title>
    <item>
      <title>USN-9999-1: curl vulnerabilities</title>
      <link>https://ubuntu.com/security/notices/USN-9999-1</link>
      <pubDate>Tue, 15 Jul 2026 10:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>
"""

RDF = """<?xml version="1.0" encoding="UTF-8" ?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns="http://purl.org/rss/1.0/"
         xmlns:dc="http://purl.org/dc/elements/1.1/">
  <item rdf:about="https://www.debian.org/security/2026/dsa-1">
    <title>DSA-1 openssl</title>
    <link>https://www.debian.org/security/2026/dsa-1</link>
    <dc:date>2026-07-14T09:00:00Z</dc:date>
  </item>
</rdf:RDF>
"""

GENTOO = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Gentoo GLSA</title>
    <item>
      <title>GLSA 202604-04: DTrace: Arbitrary file creation via dtprobed</title>
      <link>https://security.gentoo.org/glsa/202604-04</link>
      <pubDate>Fri, 17 Apr 2026 00:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>
"""

FEDORA = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Fedora security</title>
    <item>
      <title>trafficserver-10.1.3-1.fc43</title>
      <link>https://bodhi.fedoraproject.org/updates/FEDORA-2026-ddaabe38ab</link>
      <pubDate>Sat, 18 Jul 2026 23:13:00 +0000</pubDate>
      <description>Critical remote code execution in Apache Traffic Server.</description>
    </item>
  </channel>
</rss>
"""

OSS = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Open Source Security</title>
    <item>
      <title>OpenSSL HollowByte DoS via attacker-controlled allocation</title>
      <link>https://seclists.org/oss-sec/2026/q3/171</link>
      <pubDate>Sat, 18 Jul 2026 16:10:12 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


def test_parse_atom_rss_rdf() -> None:
    arch = _parse_feed_xml("Arch", ATOM)
    assert len(arch) == 1
    assert arch[0]["title"].startswith("ASA-")
    assert "ASA-202607-1" in arch[0]["link"]
    assert arch[0]["severity_label"] == "critical"

    ubuntu = _parse_feed_xml("Ubuntu", RSS)
    assert ubuntu[0]["source"] == "Ubuntu"
    assert "USN-9999-1" in ubuntu[0]["title"]
    assert ubuntu[0]["severity_label"] == "medium"

    debian = _parse_feed_xml("Debian", RDF)
    assert debian[0]["title"].startswith("DSA-")


def test_parse_gentoo_fedora_oss() -> None:
    gentoo = _parse_feed_xml("Gentoo", GENTOO)
    assert "GLSA" in gentoo[0]["title"]

    fedora = _parse_feed_xml("Fedora", FEDORA)
    # NVR title replaced with description lead-in
    assert "Traffic Server" in fedora[0]["title"] or "Critical" in fedora[0]["title"]
    assert fedora[0]["severity_label"] == "critical"

    oss = _parse_feed_xml("oss-security", OSS)
    assert oss[0]["severity_label"] == "medium"  # DoS


def test_severity_scoring() -> None:
    assert score_severity("critical RCE in foo")[1] == "critical"
    assert score_severity("important update")[1] == "high"
    assert score_severity("denial of service")[1] == "medium"
    assert score_severity("local information disclosure")[1] == "low"
    assert score_severity("routine packaging note")[1] == "unknown"


def test_merge_severity_before_date() -> None:
    """High severity older item beats low-severity newer item."""
    older_critical = {
        "source": "Arch",
        "title": "old critical RCE",
        "link": "https://example/a",
        "published": "2026-07-01T12:00:00+00:00",
        "severity": 95,
        "severity_label": "critical",
    }
    newer_low = {
        "source": "Ubuntu",
        "title": "new low",
        "link": "https://example/b",
        "published": "2026-07-18T12:00:00+00:00",
        "severity": 15,
        "severity_label": "low",
    }
    merged = _merge_items([[older_critical], [newer_low]])
    assert merged[0]["link"] == "https://example/a"
    assert merged[1]["link"] == "https://example/b"


def test_merge_and_ticker_age() -> None:
    merged = _merge_items(
        [
            _parse_feed_xml("Arch", ATOM),
            _parse_feed_xml("Ubuntu", RSS),
            _parse_feed_xml("Debian", RDF),
        ],
    )
    assert len(merged) == 3
    # Arch critical outranks Ubuntu medium despite older date
    assert merged[0]["source"] == "Arch"
    text = headlines_for_ticker({"items": merged})
    assert "Arch ·" in text
    assert "Ubuntu ·" in text
    assert "(" in text  # relative age suffix


def test_relative_age_label() -> None:
    now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
    assert relative_age_label("2026-07-18T08:00:00+00:00", now=now) == "(today)"
    assert relative_age_label("2026-07-16T08:00:00+00:00", now=now) == "(2d)"
    assert relative_age_label("2026-07-04T08:00:00+00:00", now=now) == "(2w)"


def test_normalize_source_ids() -> None:
    assert normalize_source_ids([]) == ["arch", "ubuntu", "debian"]
    assert normalize_source_ids(["fedora", "arch", "nope", "arch"]) == ["arch", "fedora"]
    assert normalize_source_ids(["bogus"]) == ["arch", "ubuntu", "debian"]
