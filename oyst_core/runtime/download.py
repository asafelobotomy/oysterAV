"""Runtime download helpers."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.request import urlopen

from oyst_core.runtime.checksums import verify_file_sha256
from oyst_core.runtime.progress import ProgressCallback, emit_progress

_logger = logging.getLogger("oyst.runtime.download")
_CHUNK = 64 * 1024


def download_file(
    url: str,
    dest: Path,
    *,
    expected_sha256: str | None = None,
    on_progress: ProgressCallback | None = None,
) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(url, timeout=180) as response:  # noqa: S310 — fixed upstream URLs
        total_header = response.headers.get("Content-Length")
        total = int(total_header) if total_header and total_header.isdigit() else 0
        written = 0
        last_pct = -1
        with dest.open("wb") as out:
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
                if total > 0:
                    pct = min(99, (written * 100) // total)
                    if pct != last_pct:
                        emit_progress(on_progress, "download", pct)
                        last_pct = pct
                elif written and written % (512 * 1024) == 0:
                    # Unknown length: pulse within 1–90 based on MB received
                    pct = min(90, 1 + (written // (512 * 1024)) % 90)
                    if pct != last_pct:
                        emit_progress(on_progress, "download", pct)
                        last_pct = pct
    emit_progress(on_progress, "download", 100)
    if not expected_sha256:
        dest.unlink(missing_ok=True)
        msg = f"refusing download without SHA-256 pin: {dest.name}"
        raise OSError(msg)
    if not verify_file_sha256(dest, expected_sha256):
        dest.unlink(missing_ok=True)
        msg = f"SHA-256 verification failed for {dest.name}"
        raise OSError(msg)
    _logger.debug("Verified SHA-256 for %s", dest.name)
    emit_progress(on_progress, "verify", 100)
