"""chkrootkit pack."""

from __future__ import annotations

import re

from oyst_core.models import Finding, FindingSeverity, PackStatus, PackTier
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.privileged.helper import run_privileged
from oyst_core.privileged.runner import run_command


class ChkrootkitPack(Pack):
    name = "chkrootkit"
    tier = PackTier.RECOMMENDED
    system_bins = ["chkrootkit"]
    min_version = "0.58"

    def doctor(self) -> PackStatus:
        path, source = resolve_pack_binary("chkrootkit", "chkrootkit")
        installed = path is not None
        version = None
        if path:
            try:
                res = run_command([path, "-V"], timeout=30)
                match = re.search(r"([\d.]+)", res.stdout + res.stderr)
                version = match.group(1) if match else None
            except (ValueError, OSError):
                version = None
        status = self._base_status(installed, version)
        if installed:
            status.details = {"tool_source": source, "binary": path}
        return status

    def scan(self) -> tuple[bool, str]:
        path, _ = resolve_pack_binary("chkrootkit", "chkrootkit")
        if not path:
            return False, "chkrootkit not installed"
        res = run_privileged([path], timeout=7200)
        return res.returncode in (0, 1), res.stdout + res.stderr

    def parse_findings(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()
            # Clean / negative results contain these substrings — not hits.
            if "not infected" in lower:
                continue
            if "no suspect" in lower:
                continue
            if "nothing found" in lower:
                continue
            if "not found" in lower and "checking" in lower:
                continue
            # Positive indicators only.
            is_hit = (
                "infected" in lower
                or "possible rootkit" in lower
                or re.search(r"\bINFECTED\b", stripped) is not None
                or ("suspect" in lower and "no suspect" not in lower)
            )
            if not is_hit:
                continue
            findings.append(
                Finding(
                    pack=self.name,
                    path="system",
                    threat_name="chkrootkit-hit",
                    severity=FindingSeverity.HIGH,
                    message=stripped,
                    raw_line=line,
                )
            )
        return findings

    def scan_paths(
        self,
        paths: list[str],
        backend: str = "auto",
        profile: str = "quick",
    ) -> list[Finding]:
        _ = (paths, backend, profile)
        ok, output = self.scan()
        if not ok and "not found" in output.lower():
            raise RuntimeError(output[:300])
        return self.parse_findings(output)
