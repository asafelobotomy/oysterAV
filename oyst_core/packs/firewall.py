"""Firewall and fail2ban status pack."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack
from oyst_core.privileged.runner import run_command, which

_DETECT_TTL_SEC = 1.5
_detect_cache: tuple[float, dict[str, object]] | None = None
_UFW_CONF = Path("/etc/ufw/ufw.conf")

_NFT_RULE_VERB_RE = re.compile(
    r"\b(accept|drop|reject|jump|goto|return|counter|masquerade|snat|dnat)\b",
    re.IGNORECASE,
)


def invalidate_firewall_detect_cache() -> None:
    """Drop cached detect() results after mutations / select / ensure."""
    global _detect_cache
    _detect_cache = None


def _ufw_enabled_from_conf(conf_path: Path = _UFW_CONF) -> bool | None:
    """Parse ENABLED= from ufw.conf when ``ufw status`` needs root. None if unknown."""
    try:
        text = conf_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        if key.strip().upper() == "ENABLED":
            return val.strip().lower() in {"yes", "true", "1"}
    return None


def _probe_ufw_active(ufw_bin: str) -> bool:
    """True when UFW is enabled (status output, else world-readable ufw.conf)."""
    try:
        res = run_command([ufw_bin, "status"], timeout=30)
        out = (res.stdout or "").lower()
        if "status: active" in out:
            return True
        if "status: inactive" in out:
            return False
    except (ValueError, OSError):
        pass
    conf = _ufw_enabled_from_conf()
    return bool(conf)


class FirewallPack(Pack):
    name = "firewall"
    tier = PackTier.RECOMMENDED
    system_bins = ["ufw", "firewall-cmd", "nft"]

    def doctor(self) -> PackStatus:
        detection = self.detect()
        managed_bins = bool(detection.get("ufw") or detection.get("firewalld"))
        version = str(detection.get("version") or "") or None
        status = self._base_status(managed_bins, version)
        status.details = detection
        active = str(detection.get("active") or "none")
        if detection.get("conflict"):
            status.message = "Multiple firewall managers detected; use only one"
        elif active in ("ufw", "firewalld"):
            status.message = f"Managed firewall active ({active})"
        elif managed_bins:
            status.message = "UFW/firewalld installed but not enabled"
        elif active == "nft-direct":
            status.message = "Host nftables filtering detected (not oysterAV-managed)"
        else:
            status.message = (
                "No active firewall; recommended on hosts with exposed network services"
            )
        return status

    def _tool_version(self, binary: str, argv: list[str], pattern: str) -> str | None:
        try:
            res = run_command([binary, *argv], timeout=15)
            match = re.search(pattern, res.stdout + res.stderr, re.IGNORECASE)
            return match.group(1) if match else None
        except (ValueError, OSError):
            return None

    @staticmethod
    def _nft_filtering_active(nft_path: str) -> bool:
        try:
            res = run_command([nft_path, "list", "ruleset"], timeout=15)
        except (ValueError, OSError):
            return False
        return bool(_NFT_RULE_VERB_RE.search(res.stdout or ""))

    def detect(self) -> dict[str, object]:
        global _detect_cache
        now = time.monotonic()
        if _detect_cache is not None and (now - _detect_cache[0]) < _DETECT_TTL_SEC:
            return dict(_detect_cache[1])
        result = self._detect_uncached()
        _detect_cache = (now, result)
        return dict(result)

    def _detect_uncached(self) -> dict[str, object]:
        ufw = which("ufw")
        fw = which("firewall-cmd")
        nft = which("nft")
        ufw_active = _probe_ufw_active(ufw) if ufw else False
        fw_active = False
        if fw:
            try:
                res = run_command(["firewall-cmd", "--state"], timeout=30)
                fw_active = res.stdout.strip().lower() == "running"
            except (ValueError, OSError):
                pass
        active = "none"
        binary = ""
        version: str | None = None
        if ufw_active and ufw:
            active = "ufw"
            binary = ufw
            version = self._tool_version(ufw, ["version"], r"ufw\s+([\d.]+)")
        elif fw_active and fw:
            active = "firewalld"
            binary = fw
            version = self._tool_version(fw, ["--version"], r"([\d.]+)")
        elif nft and self._nft_filtering_active(nft):
            active = "nft-direct"
            binary = nft
            version = self._tool_version(nft, ["--version"], r"nftables\s+v?([\d.]+)")
        conflict = ufw_active and fw_active
        return {
            "active": active,
            "binary": binary,
            "path": binary,
            "version": version or "",
            "ufw": bool(ufw),
            "firewalld": bool(fw),
            "nft": bool(nft),
            "ufw_path": ufw or "",
            "firewalld_path": fw or "",
            "nft_path": nft or "",
            "ufw_active": ufw_active,
            "firewalld_active": fw_active,
            "conflict": conflict,
        }

    def status(self) -> dict[str, object]:
        return self.detect()

    def audit(self) -> list[str]:
        recs: list[str] = []
        det = self.detect()
        if det["active"] == "none":
            recs.append("No active firewall detected; enable ufw or firewalld")
        if det.get("conflict"):
            recs.append("Disable either ufw or firewalld to avoid rule conflicts")
        if det["active"] == "ufw":
            recs.append("Review rules: sudo ufw status verbose")
        elif det["active"] == "firewalld":
            recs.append("Review zones: sudo firewall-cmd --list-all")
        elif det["active"] == "nft-direct":
            recs.append("Host nftables filtering present; oysterAV manages UFW/firewalld only")
        return recs

    def fail2ban_status(self) -> dict[str, Any]:
        if not which("fail2ban-client"):
            return {"installed": False}
        try:
            res = run_command(["fail2ban-client", "status"], timeout=30)
            return {"installed": True, "output": res.stdout.strip()}
        except (ValueError, OSError) as exc:
            return {"installed": True, "error": str(exc)}
