"""Firewall and fail2ban status pack."""

from __future__ import annotations

import re

from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack
from oyst_core.privileged.runner import run_command, which


class FirewallPack(Pack):
    name = "firewall"
    tier = PackTier.RECOMMENDED
    system_bins = ["ufw", "firewall-cmd", "nft"]

    def doctor(self) -> PackStatus:
        detection = self.detect()
        installed = detection["active"] != "none"
        version = str(detection.get("version") or "") or None
        status = self._base_status(bool(installed), version)
        status.details = detection
        if detection.get("conflict"):
            status.message = "Multiple firewall managers detected; use only one"
        elif not installed:
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

    def detect(self) -> dict[str, object]:
        ufw = which("ufw")
        fw = which("firewall-cmd")
        nft = which("nft")
        ufw_active = False
        fw_active = False
        if ufw:
            try:
                res = run_command(["ufw", "status"], timeout=30)
                ufw_active = "active" in res.stdout.lower()
            except (ValueError, OSError):
                pass
        if fw:
            try:
                res = run_command(["firewall-cmd", "--state"], timeout=30)
                fw_active = "running" in res.stdout.lower()
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
        elif nft:
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
        return recs

    def fail2ban_status(self) -> dict[str, object]:
        if not which("fail2ban-client"):
            return {"installed": False}
        try:
            res = run_command(["fail2ban-client", "status"], timeout=30)
            return {"installed": True, "output": res.stdout.strip()}
        except (ValueError, OSError) as exc:
            return {"installed": True, "error": str(exc)}
