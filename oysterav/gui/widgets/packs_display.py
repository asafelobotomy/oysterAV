"""Pack list display helpers (runtime info, subtitles, paths)."""

from __future__ import annotations

from typing import Any

from oyst_core.models import PackTier
from oyst_core.runtime.bootstrap import PACK_DESCRIPTIONS, RUNTIME_PACKS


def runtime_info(runtime: dict[str, Any], name: str) -> dict[str, Any] | None:
    packs = runtime.get("packs")
    if not isinstance(packs, dict):
        return None
    info = packs.get(name)
    return info if isinstance(info, dict) else None


def display_packs(packs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Doctor packs plus any RUNTIME_PACKS missing from doctor (as optional)."""
    out = [dict(p) for p in packs]
    seen = {str(p.get("name", "")) for p in out}
    for name in sorted(RUNTIME_PACKS):
        if name in seen:
            continue
        out.append(
            {
                "name": name,
                "installed": False,
                "tier": PackTier.OPTIONAL.value,
            },
        )
    return out


def pack_path(pack: dict[str, Any], rt: dict[str, Any] | None) -> str:
    if rt is not None:
        path = str(rt.get("path") or "").strip()
        if path:
            return path
    details = pack.get("details")
    if isinstance(details, dict):
        binary = str(details.get("binary") or "").strip()
        if binary:
            return binary
        # Firewall exposes active backend rather than a single binary.
        active = str(details.get("active") or "")
        if active and active != "none":
            for key in ("ufw_path", "firewalld_path", "nft_path", "path"):
                candidate = str(details.get(key) or "").strip()
                if candidate:
                    return candidate
            return active
    return ""


def pack_subtitle(pack: dict[str, Any], rt: dict[str, Any] | None) -> str:
    name = str(pack.get("name", ""))
    description = ""
    if rt is not None:
        description = str(rt.get("description") or "")
    if not description:
        description = PACK_DESCRIPTIONS.get(name, "")

    installed = bool(pack.get("installed"))
    private = False
    if rt is not None:
        installed = bool(rt.get("installed") or installed)
        origin = str(rt.get("origin") or rt.get("source") or "missing")
        private = bool(rt.get("private")) or origin in ("private", "runtime")

    path = pack_path(pack, rt)
    version = pack.get("version")
    version_text = f"v{version}" if version else "version unknown"

    if not installed:
        parts = [p for p in (description, "Not installed") if p]
        hint = str(pack.get("install_hint") or "").strip()
        if hint and hint not in parts:
            parts.append(hint)
        return " — ".join(parts) if parts else "Not installed"

    origin_label = "Private" if private else "System"
    meta = [origin_label]
    if path:
        meta.append(path)
    meta.append(version_text)
    meta_text = " · ".join(meta)
    if description:
        return f"{description} — {meta_text}"
    return meta_text
