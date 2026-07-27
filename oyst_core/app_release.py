"""Check for newer oysterAV releases on GitHub Releases."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from oyst_core import __version__ as INSTALLED_VERSION

_logger = logging.getLogger("oyst.app_release")

REPO = "asafelobotomy/oysterAV"
RELEASES_LATEST_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{REPO}/releases"
FETCH_TIMEOUT_S = 15
CACHE_MAX_AGE = timedelta(hours=6)
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def cache_path() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    path = base / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    return path / "app_release.json"


def parse_semver(raw: str) -> tuple[int, int, int] | None:
    """Parse ``vX.Y.Z`` / ``X.Y.Z`` (ignores pre-release / build suffix)."""
    text = str(raw or "").strip()
    match = _VERSION_RE.match(text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def version_is_newer(latest: str, current: str) -> bool:
    left = parse_semver(latest)
    right = parse_semver(current)
    if left is None or right is None:
        return False
    return left > right


def normalize_tag(tag: str) -> str:
    text = str(tag or "").strip()
    if text.lower().startswith("v") and parse_semver(text) is not None:
        return text[1:]
    return text


def _fetch_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing non-https release URL: {url!r}")
    req = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"oysterAV/{INSTALLED_VERSION} (+https://github.com/{REPO})",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(req, timeout=FETCH_TIMEOUT_S) as response:  # noqa: S310  # nosec B310
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
    return data if isinstance(data, dict) else None


def _save_cache(payload: dict[str, Any]) -> None:
    cache_path().write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _cache_fresh(payload: dict[str, Any]) -> bool:
    raw = payload.get("fetched_at")
    if not isinstance(raw, str) or not raw:
        return False
    try:
        fetched = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=UTC)
    return datetime.now(UTC) - fetched <= CACHE_MAX_AGE


def fetch_latest_release(*, force: bool = False) -> dict[str, Any]:
    """Return latest GitHub Release metadata (cached).

    Keys: ``ok``, ``tag``, ``version``, ``html_url``, ``name``, ``cached``,
    optional ``message`` on failure.
    """
    if not force:
        cached = _load_cache()
        if cached is not None and _cache_fresh(cached) and cached.get("ok"):
            out = dict(cached)
            out["cached"] = True
            return out

    try:
        body = _fetch_url(RELEASES_LATEST_URL)
        data = json.loads(body)
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as exc:
        _logger.debug("GitHub release check failed: %s", exc)
        return {
            "ok": False,
            "message": f"Could not reach GitHub Releases: {exc}",
            "html_url": RELEASES_PAGE_URL,
        }

    if not isinstance(data, dict):
        return {"ok": False, "message": "Unexpected GitHub Releases response"}

    tag = str(data.get("tag_name") or "").strip()
    version = normalize_tag(tag)
    if not tag or parse_semver(version) is None:
        return {
            "ok": False,
            "message": f"Unrecognized release tag: {tag!r}",
            "html_url": RELEASES_PAGE_URL,
        }

    html_url = str(data.get("html_url") or "").strip() or RELEASES_PAGE_URL
    payload = {
        "ok": True,
        "tag": tag,
        "version": version,
        "name": str(data.get("name") or tag).strip(),
        "html_url": html_url,
        "fetched_at": datetime.now(UTC).isoformat(),
        "cached": False,
    }
    try:
        _save_cache(payload)
    except OSError:
        pass
    return payload


def check_app_update(
    *,
    current: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Compare installed oysterAV version to the latest GitHub Release.

    When an update exists, ``update`` is a status-bar compatible dict
    (``kind=app``). Network failures set ``ok=False`` without raising.
    """
    installed = (current or INSTALLED_VERSION).strip()
    latest = fetch_latest_release(force=force)
    if not latest.get("ok"):
        return {
            "ok": False,
            "current": installed,
            "update": None,
            "message": str(latest.get("message") or "Release check failed"),
            "html_url": str(latest.get("html_url") or RELEASES_PAGE_URL),
        }

    remote = str(latest.get("version") or "")
    html_url = str(latest.get("html_url") or RELEASES_PAGE_URL)
    update: dict[str, Any] | None = None
    if version_is_newer(remote, installed):
        update = {
            "kind": "app",
            "name": "oysterAV",
            "package": "",
            "current": installed,
            "available": remote,
            "url": html_url,
            "tag": str(latest.get("tag") or ""),
        }
        message = f"oysterAV {installed} > {remote} available ({html_url})"
    elif version_is_newer(installed, remote):
        message = f"oysterAV {installed} is newer than latest GitHub Release {remote}"
    else:
        message = f"oysterAV {installed} is up to date (latest {remote})"
    return {
        "ok": True,
        "current": installed,
        "latest": remote,
        "html_url": html_url,
        "update": update,
        "message": message,
        "cached": bool(latest.get("cached")),
    }


def app_update_entry(*, force: bool = False) -> dict[str, Any] | None:
    """Return a single updates-list entry when a newer release exists."""
    result = check_app_update(force=force)
    update = result.get("update")
    return update if isinstance(update, dict) else None
