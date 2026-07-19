"""Runtime manifest and architecture detection."""

from __future__ import annotations

import json
import platform
from pathlib import Path

from pydantic import BaseModel, Field

from oyst_core.config import RuntimeMode, data_dir, load_config

RUNTIME_VERSION = "0.1.0"


class RuntimeArtifact(BaseModel):
    name: str
    version: str = ""
    path: str
    sha256: str = ""
    source: str = ""


class RuntimeLock(BaseModel):
    version: str = RUNTIME_VERSION
    arch: str = ""
    mode: RuntimeMode = "full"
    artifacts: list[RuntimeArtifact] = Field(default_factory=list)


PACK_TOOL_NAMES: dict[str, list[str]] = {
    "clamav": ["clamscan", "clamdscan"],
    "freshclam": ["freshclam"],
    "clamonacc": ["clamonacc", "clamd"],
    "rkhunter": ["rkhunter"],
    "chkrootkit": ["chkrootkit"],
    "lynis": ["lynis"],
    "maldet": ["maldet"],
    "unhide": ["unhide", "unhide-linux"],
    "fangfrisch": ["fangfrisch"],
}


def detect_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return machine


def runtime_root() -> Path:
    root = data_dir() / "runtime" / detect_arch()
    root.mkdir(parents=True, exist_ok=True)
    return root


def runtime_bin_dir() -> Path:
    path = runtime_root() / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


def runtime_lock_path() -> Path:
    return runtime_root() / "runtime.lock.json"


def is_full_mode() -> bool:
    return load_config().runtime.mode == "full"


def is_lite_mode() -> bool:
    return load_config().runtime.mode == "lite"


def runtime_maldet_prefix() -> Path:
    return runtime_root() / "maldetect"


def load_runtime_lock() -> RuntimeLock:
    path = runtime_lock_path()
    if not path.is_file():
        lock = RuntimeLock(arch=detect_arch(), mode=load_config().runtime.mode)
        save_runtime_lock(lock)
        return lock
    data = json.loads(path.read_text(encoding="utf-8"))
    return RuntimeLock.model_validate(data)


def save_runtime_lock(lock: RuntimeLock) -> None:
    lock.arch = detect_arch()
    lock.mode = load_config().runtime.mode
    runtime_lock_path().write_text(lock.model_dump_json(indent=2), encoding="utf-8")


def record_artifact(name: str, path: Path, *, version: str = "", source: str = "") -> None:
    lock = load_runtime_lock()
    rel = (
        str(path.relative_to(runtime_root())) if path.is_relative_to(runtime_root()) else str(path)
    )
    lock.artifacts = [a for a in lock.artifacts if a.name != name]
    lock.artifacts.append(
        RuntimeArtifact(name=name, version=version, path=rel, source=source),
    )
    save_runtime_lock(lock)


def clear_artifacts(name: str) -> list[str]:
    """Remove lock entries for pack name (and related tool artifact names)."""
    lock = load_runtime_lock()
    related = {name, *PACK_TOOL_NAMES.get(name, [])}
    if name == "clamav":
        related.update({"clamscan", "clamdscan", "clamd", "freshclam", "clamonacc"})
    kept = [a for a in lock.artifacts if a.name not in related]
    removed = [a.name for a in lock.artifacts if a.name in related]
    lock.artifacts = kept
    save_runtime_lock(lock)
    return removed


def artifact_installed(name: str) -> bool:
    lock = load_runtime_lock()
    for artifact in lock.artifacts:
        if artifact.name == name:
            candidate = runtime_root() / artifact.path
            return candidate.is_file() or candidate.is_dir()
    return False
