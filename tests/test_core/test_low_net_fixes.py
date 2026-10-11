"""Regression tests for Low-severity supply-chain / network audit findings."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from oyst_core import net_util
from oyst_core.net_util import HttpsOnlyRedirectHandler, read_limited, stream_to_path

ROOT = Path(__file__).resolve().parents[2]


class _Resp:
    def __init__(self, data: bytes, *, length: int | None = None) -> None:
        self._buf = io.BytesIO(data)
        self.headers: dict[str, str] = {} if length is None else {"Content-Length": str(length)}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_a: object) -> None:
        return None


# --- 7. bounded downloads -----------------------------------------------------


def test_stream_to_path_aborts_and_deletes_partial(tmp_path: Path) -> None:
    dest = tmp_path / "blob"
    with pytest.raises(OSError, match="size limit"):
        stream_to_path(_Resp(b"x" * 300_000), dest, max_bytes=100_000)
    assert not dest.exists()


def test_stream_to_path_honors_content_length(tmp_path: Path) -> None:
    dest = tmp_path / "blob"
    with pytest.raises(OSError, match="size limit"):
        stream_to_path(_Resp(b"", length=10**12), dest, max_bytes=1024)
    assert not dest.exists()


def test_read_limited_caps_memory() -> None:
    assert read_limited(_Resp(b"abc"), 10) == b"abc"
    with pytest.raises(OSError):
        read_limited(_Resp(b"x" * 100), 10)


def test_download_file_respects_max_bytes(tmp_path: Path) -> None:
    from oyst_core.runtime.download import download_file

    payload = b"y" * 200_000
    dest = tmp_path / "out.bin"
    with (
        patch("oyst_core.runtime.download.https_urlopen", return_value=_Resp(payload)),
        pytest.raises(OSError, match="size limit"),
    ):
        download_file(
            "https://example.test/x",
            dest,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            max_bytes=1000,
        )
    assert not dest.exists()


def test_pack_sources_download_streams_with_limit(tmp_path: Path) -> None:
    from oyst_core import pack_sources

    dest = tmp_path / "m.tgz"
    with (
        patch.object(net_util, "https_urlopen", return_value=_Resp(b"z" * 5000)),
        pytest.raises(OSError, match="size limit"),
    ):
        pack_sources._download("https://example.test/m.tgz", dest, max_bytes=100)
    assert not dest.exists()


# --- 8. https-only redirects ------------------------------------------------------


@pytest.mark.parametrize("target", ["http://evil.test/x", "file:///etc/passwd", "ftp://x/y"])
def test_redirect_to_non_https_refused(target: str) -> None:
    handler = HttpsOnlyRedirectHandler()
    req = Request("https://example.test/start")
    with pytest.raises(HTTPError, match="non-https redirect"):
        handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, target)  # type: ignore[arg-type]


def test_redirect_to_https_allowed() -> None:
    handler = HttpsOnlyRedirectHandler()
    req = Request("https://example.test/start")
    new = handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, "https://cdn.test/f")  # type: ignore[arg-type]
    assert new is not None and new.full_url == "https://cdn.test/f"


def test_https_urlopen_refuses_http() -> None:
    with pytest.raises(ValueError, match="non-https"):
        net_util.https_urlopen("http://example.test/", timeout=1)


@pytest.mark.parametrize(
    "module", ["oyst_core.app_release", "oyst_core.security_news_fetch", "oyst_core.pack_sources"]
)
def test_modules_use_shared_opener(module: str) -> None:
    source = (ROOT / (module.replace(".", "/") + ".py")).read_text()
    assert "urlopen(" not in source.replace("https_urlopen(", "")


# --- 9. release html_url pinned to the repo ------------------------------------------


@pytest.mark.parametrize(
    ("raw", "ok"),
    [
        ("https://github.com/asafelobotomy/oysterAV/releases/tag/v9.9.9", True),
        ("https://evil.test/asafelobotomy/oysterAV/", False),
        ("https://github.com/asafelobotomy/oysterAV.evil/x", False),
        ("javascript:alert(1)", False),
        (None, False),
    ],
)
def test_release_html_url_validated(raw: Any, ok: bool) -> None:
    from oyst_core import app_release

    payload = {"tag_name": "v9.9.9", "html_url": raw}
    with (
        patch("oyst_core.app_release._fetch_url", return_value=json.dumps(payload)),
        patch("oyst_core.app_release._save_cache"),
    ):
        result = app_release.fetch_latest_release(force=True)
    expected = raw if ok else app_release.RELEASES_PAGE_URL
    assert result["html_url"] == expected


# --- 10. feed link schemes + control characters --------------------------------------


def test_feed_links_and_control_chars_sanitized() -> None:
    from oyst_core.security_news_parse import parse_feed_xml

    xml = (
        '<?xml version="1.0"?><rss version="2.0"><channel>'
        "<item><title>Bad\u0085 title\u009b</title><link>file:///etc/passwd</link></item>"
        "<item><title>Smb‮</title><link>smb://host/share</link></item>"
        "<item><title>Good</title><link>https://example.test/a</link></item>"
        "</channel></rss>"
    )
    items = parse_feed_xml("src", xml)
    by_title = {i["title"]: i for i in items}
    assert by_title["Bad title"]["link"] == ""
    assert by_title["Smb"]["link"] == ""
    assert by_title["Good"]["link"] == "https://example.test/a"


def test_strip_control_chars_keeps_newline_tab() -> None:
    from oyst_core.security_news_parse import safe_link, strip_control_chars

    assert strip_control_chars("a\tb\nc\x1b[31m\u009b​") == "a\tb\nc[31m"
    assert safe_link("http://x.test/p") == "http://x.test/p"
    assert safe_link("javascript:alert(1)") == ""
    assert safe_link("https://x.test/a b") == ""


# --- 11. versioned maldet URL -----------------------------------------------------------


def test_maldet_url_is_versioned() -> None:
    from oyst_core.pack_sources import MALDET_URL, MALDET_VERSION

    assert "current" not in MALDET_URL
    assert MALDET_URL.endswith(f"/maldetect-{MALDET_VERSION}.tar.gz")
    assert MALDET_URL.startswith("https://www.rfxn.com/downloads/")


# --- 12. build_runtime.sh uses mktemp ---------------------------------------------------


def test_build_runtime_uses_private_tempdir() -> None:
    script = (ROOT / "scripts" / "build_runtime.sh").read_text()
    assert "/tmp/lynis.tar.gz" not in script
    assert "mktemp -d" in script
    assert "trap " in script
    subprocess.run(["bash", "-n", str(ROOT / "scripts" / "build_runtime.sh")], check=True)
