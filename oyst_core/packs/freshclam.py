"""freshclam pack."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack, detect_distro_family, resolve_pack_binary
from oyst_core.privileged.runner import run_command
from oyst_core.runtime.bundles.clamav import (
    clamav_db_dir,
    freshclam_conf_path,
    update_clamav_signatures,
)

DAILY_CVD = [
    "/var/lib/clamav/daily.cvd",
    "/var/lib/clamav/daily.cld",
    "/var/lib/clamav/main.cvd",
]


class FreshclamPack(Pack):
    name = "freshclam"
    tier = PackTier.REQUIRED
    system_bins = ["freshclam"]

    def _detect_version(self, path: str | None) -> str | None:
        if path:
            try:
                res = run_command([path, "--version"], timeout=30)
                match = re.search(r"ClamAV\s+([\d.]+)", res.stdout + res.stderr)
                if match:
                    return match.group(1)
            except (ValueError, OSError):
                pass
        # Lazy import: clamav imports resolve helpers that can pull pack modules.
        from oyst_core.packs.clamav import ClamAVPack

        return ClamAVPack()._detect_version()

    def doctor(self) -> PackStatus:
        path, source = resolve_pack_binary("freshclam", "freshclam")
        installed = path is not None
        version = self._detect_version(path) if installed else None
        status = self._base_status(installed, version)
        if installed:
            age = self.signature_age_hours()
            runtime_db = clamav_db_dir()
            yara_count = len(list(runtime_db.glob("*.yar"))) + len(list(runtime_db.glob("*.yara")))
            status.details = {
                "signature_age_hours": age,
                "tool_source": source,
                "binary": path,
                "yara_rules_in_db": yara_count,
                "db_dir": str(runtime_db),
            }
            if age is not None and age > 48:
                family = detect_distro_family()
                timer_hint = (
                    "sudo systemctl enable --now clamav-freshclam.timer"
                    if family != "arch"
                    else "Enable periodic updates via your distro's clamav timer"
                )
                status.message = (
                    f"Signatures are {age:.0f}h old; run freshclam update or {timer_hint}"
                )
        return status

    def signature_age_hours(self) -> float | None:
        newest: float | None = None
        runtime_db = clamav_db_dir()
        candidates = list(DAILY_CVD) + [str(p) for p in runtime_db.glob("*.cvd")]
        candidates.extend(str(p) for p in runtime_db.glob("*.cld"))
        for cvd in candidates:
            p = Path(cvd)
            if p.exists():
                mtime = p.stat().st_mtime
                if newest is None or mtime > newest:
                    newest = mtime
        if newest is None:
            return None
        return (datetime.now().timestamp() - newest) / 3600.0

    def update(self) -> tuple[bool, str]:
        path, _ = resolve_pack_binary("freshclam", "freshclam")
        if not path:
            return False, "freshclam not installed"
        if freshclam_conf_path().is_file():
            result = update_clamav_signatures()
            return bool(result.get("ok")), str(result.get("message", ""))
        res = run_command([path], timeout=1800)
        ok = res.returncode == 0
        msg = res.stdout or res.stderr
        return ok, msg.strip()

    def status_text(self) -> dict[str, str | float | None]:
        age = self.signature_age_hours()
        path, _ = resolve_pack_binary("freshclam", "freshclam")
        log_path = Path("/var/log/clamav/freshclam.log")
        last_run = None
        if log_path.exists():
            try:
                lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in reversed(lines[-50:]):
                    if "updated" in line.lower():
                        match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                        if match:
                            last_run = match.group(1)
                        break
            except OSError:
                pass
        return {
            "signature_age_hours": age,
            "last_run": last_run,
            "freshclam_path": path,
        }
