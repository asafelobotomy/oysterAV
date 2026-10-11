"""Runtime download helpers."""

from __future__ import annotations

import logging
from pathlib import Path

from oyst_core.net_util import (
    DEFAULT_MAX_DOWNLOAD_BYTES,
    ChunkCallback,
    https_urlopen,
    require_https,
    stream_to_path,
)
from oyst_core.runtime.checksums import verify_file_sha256
from oyst_core.runtime.progress import ProgressCallback, emit_progress

_logger = logging.getLogger("oyst.runtime.download")
_PULSE = 512 * 1024


def _progress_reporter(on_progress: ProgressCallback | None) -> ChunkCallback:
    last_pct = -1

    def report(written: int, total: int) -> None:
        nonlocal last_pct
        if total > 0:
            pct = min(99, (written * 100) // total)
        elif written and written % _PULSE == 0:
            # Unknown length: pulse within 1–90 based on 512 KiB blocks received
            pct = min(90, 1 + (written // _PULSE) % 90)
        else:
            return
        if pct != last_pct:
            emit_progress(on_progress, "download", pct)
            last_pct = pct

    return report


def download_file(
    url: str,
    dest: Path,
    *,
    expected_sha256: str | None = None,
    on_progress: ProgressCallback | None = None,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES,
) -> None:
    require_https(url)
    if not expected_sha256:
        msg = f"refusing download without SHA-256 pin: {dest.name}"
        raise OSError(msg)
    dest.parent.mkdir(parents=True, exist_ok=True)
    report = _progress_reporter(on_progress)
    with https_urlopen(url, timeout=180) as response:
        stream_to_path(response, dest, max_bytes=max_bytes, on_chunk=report)
    emit_progress(on_progress, "download", 100)
    if not verify_file_sha256(dest, expected_sha256):
        dest.unlink(missing_ok=True)
        msg = f"SHA-256 verification failed for {dest.name}"
        raise OSError(msg)
    _logger.debug("Verified SHA-256 for %s", dest.name)
    emit_progress(on_progress, "verify", 100)
