"""SHA-256 checksum manifest for runtime tarball downloads."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

_MANIFEST_PATH = Path(__file__).resolve().parent / "checksums.json"


def load_checksums() -> dict[str, str]:
    if not _MANIFEST_PATH.is_file():
        return {}
    raw = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v}


def verify_file_sha256(path: Path, expected: str) -> bool:
    if not expected:
        return False
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest.lower() == expected.lower()


def require_checksum_for_key(key: str) -> str:
    value = checksum_for_key(key)
    if not value:
        msg = f"missing in-repo SHA-256 pin for runtime artifact: {key}"
        raise OSError(msg)
    return value


def checksum_for_key(key: str) -> str | None:
    value = load_checksums().get(key)
    return value if value else None
