"""Shared HTTPS-only urllib helpers: redirect policy and bounded reads."""

from __future__ import annotations

import os
from collections.abc import Callable
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

DEFAULT_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 8 * 1024 * 1024
_CHUNK = 64 * 1024

type ChunkCallback = Callable[[int, int], None]


def require_https(url: str, what: str = "download") -> None:
    """Raise ``ValueError`` unless ``url`` is an absolute ``https://`` URL."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing non-https {what} URL: {url!r}")


class HttpsOnlyRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only when the target is another ``https://`` URL."""

    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or not parsed.netloc:
            raise HTTPError(
                newurl,
                code,
                f"refusing non-https redirect to {newurl!r}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER: OpenerDirector = build_opener(HttpsOnlyRedirectHandler())


def https_urlopen(url: str | Request, *, timeout: float) -> Any:
    """Open an ``https://`` URL; redirects to non-https targets are refused."""
    full_url = url.full_url if isinstance(url, Request) else url
    require_https(full_url)
    return _OPENER.open(url, timeout=timeout)


def declared_length(response: Any) -> int:
    """Return the response ``Content-Length`` (0 when absent or invalid)."""
    raw = response.headers.get("Content-Length")
    text = str(raw).strip() if raw is not None else ""
    return int(text) if text.isdigit() else 0


def _too_large(max_bytes: int) -> OSError:
    return OSError(f"download exceeds size limit of {max_bytes} bytes")


def read_limited(response: Any, max_bytes: int = DEFAULT_MAX_TEXT_BYTES) -> bytes:
    """Read a response body into memory, refusing bodies over ``max_bytes``."""
    if declared_length(response) > max_bytes:
        raise _too_large(max_bytes)
    parts: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise _too_large(max_bytes)
        parts.append(chunk)
    return b"".join(parts)


def stream_to_path(
    response: Any,
    dest: Path,
    *,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    on_chunk: ChunkCallback | None = None,
) -> int:
    """Stream ``response`` to ``dest`` in chunks; delete the partial file on error.

    ``on_chunk(written, declared_total)`` is called after each chunk.
    Returns the number of bytes written.
    """
    total = declared_length(response)
    if total > max_bytes:
        raise _too_large(max_bytes)
    written = 0
    try:
        fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise _too_large(max_bytes)
                out.write(chunk)
                if on_chunk is not None:
                    on_chunk(written, total)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return written


def download_to_path(
    url: str,
    dest: Path,
    *,
    timeout: float,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
    on_chunk: ChunkCallback | None = None,
) -> int:
    """Download an ``https://`` URL to ``dest`` with a size cap."""
    require_https(url)
    with https_urlopen(url, timeout=timeout) as response:
        return stream_to_path(response, dest, max_bytes=max_bytes, on_chunk=on_chunk)


__all__ = [
    "DEFAULT_MAX_DOWNLOAD_BYTES",
    "DEFAULT_MAX_TEXT_BYTES",
    "ChunkCallback",
    "HttpsOnlyRedirectHandler",
    "declared_length",
    "download_to_path",
    "https_urlopen",
    "read_limited",
    "require_https",
    "stream_to_path",
]
