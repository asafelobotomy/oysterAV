"""Resolve pack tool binaries from runtime or system PATH."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from oyst_core.privileged.runner import which
from oyst_core.runtime.manifest import (
    PACK_TOOL_NAMES,
    artifact_installed,
    is_full_mode,
    is_lite_mode,
    runtime_bin_dir,
    runtime_maldet_prefix,
    runtime_root,
)


@dataclass(frozen=True)
class ResolvedTool:
    path: str | None
    source: str  # runtime | system | missing
    command: str


def _runtime_candidates(tool: str) -> list[Path]:
    root = runtime_root()
    candidates = [
        runtime_bin_dir() / tool,
        root / "chkrootkit" / tool,
        root / "rkhunter" / "usr" / "bin" / tool,
        root / "rkhunter" / tool,
        root / "unhide" / tool,
    ]
    if tool == "lynis":
        candidates[:0] = [root / "lynis" / "lynis", root / "lynis" / tool]
    if tool == "maldet":
        candidates.insert(0, runtime_maldet_prefix() / "maldet")
        candidates.insert(1, runtime_maldet_prefix() / "bin" / tool)
    return candidates


def resolve_tool(tool: str) -> ResolvedTool:
    if is_full_mode():
        for candidate in _runtime_candidates(tool):
            if candidate.is_file():
                return ResolvedTool(str(candidate), "runtime", tool)
    found = which(tool)
    if found:
        return ResolvedTool(found, "system", tool)
    if is_lite_mode():
        return ResolvedTool(None, "missing", tool)
    for candidate in _runtime_candidates(tool):
        if candidate.is_file():
            return ResolvedTool(str(candidate), "runtime", tool)
    return ResolvedTool(None, "missing", tool)


def resolve_pack_tool(pack_name: str, preferred: str | None = None) -> ResolvedTool:
    tools = PACK_TOOL_NAMES.get(pack_name, [])
    if preferred:
        tools = [preferred, *tools]
    seen: set[str] = set()
    for tool in tools:
        if tool in seen:
            continue
        seen.add(tool)
        resolved = resolve_tool(tool)
        if resolved.path:
            return resolved
    primary = preferred or (tools[0] if tools else pack_name)
    return ResolvedTool(None, "missing", primary)


def pack_available_in_runtime(pack_name: str) -> bool:
    if artifact_installed(pack_name):
        return True
    resolved = resolve_pack_tool(pack_name)
    return resolved.source == "runtime" and resolved.path is not None


def tool_env_path() -> str:
    paths = [str(runtime_bin_dir()), str(runtime_root() / "lynis")]
    maldet = runtime_maldet_prefix()
    if maldet.is_dir():
        paths.append(str(maldet))
    existing = os.environ.get("PATH", "")
    return os.pathsep.join([*paths, existing]) if existing else os.pathsep.join(paths)


def copy_system_tool(tool: str) -> Path | None:
    """Copy a system binary into runtime bin when bootstrapping."""
    source = which(tool)
    if not source:
        return None
    dest = runtime_bin_dir() / tool
    shutil.copy2(source, dest)
    dest.chmod(dest.stat().st_mode | 0o111)
    return dest
