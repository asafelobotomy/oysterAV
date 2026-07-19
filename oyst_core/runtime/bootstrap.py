"""Bootstrap vendored pack runtimes."""

from __future__ import annotations

import hashlib
import lzma
import shutil
import tarfile
from pathlib import Path

from oyst_core.runtime.bundles.clamav import bootstrap_clamav_runtime, update_clamav_signatures
from oyst_core.runtime.bundles.scanners import (
    install_chkrootkit_runtime,
    install_fangfrisch_runtime,
    install_lynis_runtime,
    install_maldet_runtime_tree,
    install_rkhunter_runtime,
    install_unhide_runtime,
)
from oyst_core.runtime.manifest import (
    PACK_TOOL_NAMES,
    RUNTIME_VERSION,
    clear_artifacts,
    is_full_mode,
    load_runtime_lock,
    record_artifact,
    runtime_bin_dir,
    runtime_maldet_prefix,
    runtime_root,
    save_runtime_lock,
)
from oyst_core.runtime.progress import ProgressCallback, emit_progress
from oyst_core.runtime.resolver import pack_available_in_runtime, resolve_pack_tool

RUNTIME_PACKS = frozenset(
    {
        "clamav",
        "freshclam",
        "clamonacc",
        "rkhunter",
        "chkrootkit",
        "lynis",
        "maldet",
        "unhide",
        "fangfrisch",
    },
)

PACK_DESCRIPTIONS: dict[str, str] = {
    "clamav": "On-demand malware scanner (clamscan / clamd)",
    "freshclam": "Updates ClamAV virus definition databases",
    "clamonacc": "On-access / real-time ClamAV file monitoring",
    "rkhunter": "Rootkit hunter — checks binaries and system integrity",
    "chkrootkit": "Classic rootkit detection checks on the local system",
    "lynis": "Security auditing and hardening suggestions",
    "maldet": "Linux Malware Detect — malware scanner for web data",
    "unhide": "Detects hidden processes and ports",
    "fangfrisch": "Unofficial ClamAV signature providers (complements freshclam)",
    "firewall": "Host firewall (ufw, firewalld, or nftables)",
    "fail2ban": "Intrusion prevention — bans IPs that show malicious signs",
}

# Pack-specific directories/bin names under the private runtime root.
_PACK_DIRS: dict[str, tuple[str, ...]] = {
    "clamav": ("clamav",),
    "freshclam": (),
    "clamonacc": (),
    "lynis": ("lynis",),
    "maldet": ("maldetect",),
    "chkrootkit": ("chkrootkit",),
    "rkhunter": ("rkhunter",),
    "unhide": ("unhide",),
    "fangfrisch": ("fangfrisch",),
}
_PACK_BIN_LINKS: dict[str, tuple[str, ...]] = {
    "clamav": ("clamscan", "clamdscan", "clamd"),
    "freshclam": ("freshclam",),
    "clamonacc": ("clamonacc",),
    "lynis": (),
    "maldet": ("maldet",),
    "chkrootkit": ("chkrootkit",),
    "rkhunter": ("rkhunter",),
    "unhide": ("unhide", "unhide-linux"),
    "fangfrisch": ("fangfrisch",),
}


def runtime_status() -> dict[str, object]:
    lock = load_runtime_lock()
    packs: dict[str, object] = {}
    for name in sorted(RUNTIME_PACKS):
        resolved = resolve_pack_tool(name)
        source = resolved.source
        installed = resolved.path is not None and source != "missing"
        origin = (
            "private" if source == "runtime" else ("system" if source == "system" else "missing")
        )
        packs[name] = {
            "installed": installed,
            "source": source,
            "origin": origin,
            "path": resolved.path or "",
            "private": source == "runtime",
            "description": PACK_DESCRIPTIONS.get(name, ""),
        }
    total_bytes = sum(f.stat().st_size for f in runtime_root().rglob("*") if f.is_file())
    return {
        "mode": lock.mode,
        "version": lock.version,
        "arch": lock.arch,
        "root": str(runtime_root()),
        "disk_bytes": total_bytes,
        "packs": packs,
        "artifacts": [a.model_dump() for a in lock.artifacts],
    }


def install_maldet_runtime(source_dir: Path) -> Path:
    dest = install_maldet_runtime_tree(source_dir)
    record_artifact("maldet", dest, source="tarball")
    return dest


def _configure_fangfrisch_after_install() -> None:
    """Write managed conf and initdb so refresh/maintenance can run immediately."""
    from oyst_core.packs.fangfrisch import FangfrischPack

    pack = FangfrischPack()
    pack.ensure_config()
    pack.initdb()


def install_pack_runtime(
    name: str,
    *,
    on_progress: ProgressCallback | None = None,
) -> dict[str, object]:
    if name not in RUNTIME_PACKS:
        return {"ok": False, "message": f"Pack {name} is not runtime-bundled (use system install)"}
    if not is_full_mode():
        return {"ok": False, "message": "Runtime install requires full mode (runtime.mode=full)"}
    emit_progress(on_progress, "install", 0)
    try:
        if name in ("clamav", "freshclam", "clamonacc"):
            result = bootstrap_clamav_runtime(on_progress=on_progress)
        elif name == "lynis":
            result = install_lynis_runtime(on_progress=on_progress)
        elif name == "maldet":
            from oyst_core.pack_sources import install_maldet_tarball

            emit_progress(on_progress, "download", 10)
            res = install_maldet_tarball()
            result = {"ok": res.returncode == 0, "message": res.stderr or res.stdout}
            if result.get("ok"):
                record_artifact(name, runtime_maldet_prefix(), source="tarball")
                emit_progress(on_progress, "install", 100)
            return {**result, "pack": name}
        elif name == "chkrootkit":
            result = install_chkrootkit_runtime(on_progress=on_progress)
        elif name == "rkhunter":
            result = install_rkhunter_runtime(on_progress=on_progress)
        elif name == "unhide":
            result = install_unhide_runtime(on_progress=on_progress)
        elif name == "fangfrisch":
            result = install_fangfrisch_runtime(on_progress=on_progress)
            if result.get("ok"):
                _configure_fangfrisch_after_install()
        else:
            result = {"ok": False, "message": f"No bootstrap recipe for {name}"}
        if result.get("ok"):
            if name == "maldet":
                record_artifact(name, runtime_maldet_prefix(), source="bootstrap")
            elif name in ("clamav", "freshclam", "clamonacc"):
                record_artifact(name, runtime_root() / "clamav", source="bootstrap")
            elif name == "fangfrisch":
                # Already recorded by install_fangfrisch_runtime.
                pass
            else:
                pack_dir = runtime_root() / name
                if pack_dir.exists():
                    record_artifact(name, pack_dir, source="bootstrap")
                else:
                    tool = resolve_pack_tool(name)
                    if tool.path:
                        record_artifact(name, Path(tool.path), source="bootstrap")
            emit_progress(on_progress, "install", 100)
        return {**result, "pack": name}
    except OSError as exc:
        return {"ok": False, "message": str(exc), "pack": name}


def _unlink_bin(name: str) -> None:
    link = runtime_bin_dir() / name
    if link.exists() or link.is_symlink():
        link.unlink()


def remove_pack_runtime(
    name: str,
    *,
    on_progress: ProgressCallback | None = None,
) -> dict[str, object]:
    """Remove private runtime artifacts for a pack (not host packages)."""
    if name not in RUNTIME_PACKS:
        return {"ok": False, "message": f"Pack {name} is not runtime-bundled", "pack": name}
    if not is_full_mode():
        return {
            "ok": False,
            "message": "Runtime remove requires full mode (runtime.mode=full)",
            "pack": name,
        }

    emit_progress(on_progress, "remove", 0)
    root = runtime_root()
    removed_paths: list[str] = []
    had_runtime = pack_available_in_runtime(name)

    # Also accept lock artifacts even if resolve no longer sees the tool.
    lock = load_runtime_lock()
    related_names = {name, *PACK_TOOL_NAMES.get(name, [])}
    if name in ("clamav", "freshclam", "clamonacc"):
        related_names.update({"clamscan", "clamdscan", "clamd", "freshclam", "clamonacc", "clamav"})
    lock_hits = [a for a in lock.artifacts if a.name in related_names]
    if (
        not had_runtime
        and not lock_hits
        and not any((root / d).exists() for d in _PACK_DIRS.get(name, ()))
    ):
        return {
            "ok": False,
            "message": f"No private runtime install found for {name}",
            "pack": name,
        }

    emit_progress(on_progress, "remove", 20)
    for dirname in _PACK_DIRS.get(name, ()):
        path = root / dirname
        # Shared clamav/ dir: only remove when removing clamav (primary).
        if name in ("freshclam", "clamonacc") and dirname == "clamav":
            continue
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed_paths.append(str(path))

    emit_progress(on_progress, "remove", 60)
    for bin_name in _PACK_BIN_LINKS.get(name, ()):
        link = runtime_bin_dir() / bin_name
        if link.exists() or link.is_symlink():
            removed_paths.append(str(link))
            _unlink_bin(bin_name)

    # Remove recorded artifact files that sit under runtime (not whole root).
    for artifact in lock_hits:
        candidate = root / artifact.path
        if candidate.resolve() == root.resolve():
            continue
        if candidate.exists():
            if candidate.is_dir():
                shutil.rmtree(candidate, ignore_errors=True)
            else:
                candidate.unlink(missing_ok=True)
            removed_paths.append(str(candidate))

    emit_progress(on_progress, "remove", 85)
    cleared = clear_artifacts(name)
    emit_progress(on_progress, "remove", 100)

    if not removed_paths and not cleared:
        return {
            "ok": False,
            "message": f"No private runtime install found for {name}",
            "pack": name,
        }

    return {
        "ok": True,
        "message": f"Removed {name} from private runtime",
        "pack": name,
        "removed": sorted(set(removed_paths)),
        "artifacts_cleared": cleared,
    }


def bootstrap_runtime(
    packs: list[str] | None = None,
    *,
    on_progress: ProgressCallback | None = None,
) -> list[dict[str, object]]:
    targets = list(packs or sorted(RUNTIME_PACKS))
    # Collapse clamav family when installing all
    filtered: list[str] = []
    for name in targets:
        if name == "freshclam" and "clamav" in targets:
            continue
        if name == "clamonacc" and "clamav" in targets:
            continue
        filtered.append(name)
    results: list[dict[str, object]] = []
    total = max(1, len(filtered))
    for idx, name in enumerate(filtered):
        start = (idx * 100) // total
        end = ((idx + 1) * 100) // total

        def _nested(
            stage: str,
            percent: int,
            _start: int = start,
            _end: int = end,
            _name: str = name,
        ) -> None:
            span = max(0, _end - _start)
            overall = _start + (span * max(0, min(100, percent))) // 100
            emit_progress(on_progress, f"{_name}:{stage}", overall)

        entry = install_pack_runtime(name, on_progress=_nested if on_progress else None)
        entry["pack"] = name
        results.append(entry)
    lock = load_runtime_lock()
    lock.version = RUNTIME_VERSION
    save_runtime_lock(lock)
    emit_progress(on_progress, "bootstrap", 100)
    return results


def update_runtime() -> dict[str, object]:
    sig = update_clamav_signatures()
    return {"ok": sig.get("ok", False), "clamav": sig, "status": runtime_status()}


def extract_zst_archive(archive_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with lzma.open(archive_path, "rb") as src:
        with tarfile.open(fileobj=src, mode="r:") as archive:
            archive.extractall(dest, filter="data")


def verify_sha256(path: Path, expected: str) -> bool:
    if not expected:
        return True
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest == expected
