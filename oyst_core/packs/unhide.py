"""Optional unhide pack (v1.1)."""

from __future__ import annotations

import re
from pathlib import Path

from oyst_core.models import Finding, FindingSeverity, PackStatus, PackTier
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.privileged.helper_validate import resolve_trusted_binary
from oyst_core.privileged.runner import run_command
from oyst_core.privileged.scanner_exec import (
    privileged_scanner_unavailable_message,
    run_privileged_scanner,
)


class UnhidePack(Pack):
    name = "unhide"
    tier = PackTier.OPTIONAL
    system_bins = ["unhide", "unhide-linux"]

    def _binary(self) -> str | None:
        path, _ = resolve_pack_binary("unhide", "unhide-linux")
        if path:
            return path
        return resolve_pack_binary("unhide", "unhide")[0]

    def _detect_version(self, path: str | None) -> str | None:
        if not path:
            return None
        try:
            res = run_command([path, "--version"], timeout=15)
            match = re.search(r"Unhide\s+(\S+)", res.stdout + res.stderr, re.IGNORECASE)
            if match:
                return match.group(1)
        except (ValueError, OSError):
            pass
        return None

    def doctor(self) -> PackStatus:
        path = self._binary()
        _p, source = resolve_pack_binary("unhide", "unhide-linux")
        version = self._detect_version(path) if path else None
        status = self._base_status(path is not None, version)
        if path:
            status.details = {"tool_source": source, "binary": path}
            if source == "runtime":
                try:
                    resolve_trusted_binary(Path(path).name)
                except ValueError:
                    status.message = privileged_scanner_unavailable_message("unhide")
        return status

    def scan(self, mode: str = "sys") -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "unhide not installed"
        allowed = {"sys", "brute", "quick", "check", "fork", "proc", "reverse"}
        scan_mode = mode if mode in allowed else "sys"
        res = run_privileged_scanner(binary, [scan_mode], timeout=600)
        return res.returncode == 0, res.stdout + res.stderr

    def parse_findings(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            if "found" in line.lower() and "hidden" in line.lower():
                findings.append(
                    Finding(
                        pack=self.name,
                        path="process",
                        threat_name="hidden-process",
                        severity=FindingSeverity.HIGH,
                        message=line.strip(),
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
        if not ok and "not installed" in output:
            return []
        return self.parse_findings(output)
