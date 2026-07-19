"""rkhunter pack."""

from __future__ import annotations

import re

from oyst_core.models import Finding, FindingSeverity, PackStatus, PackTier
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.packs.rkhunter_resolve import ensure_disable_tests_overlay
from oyst_core.privileged.helper import run_privileged
from oyst_core.privileged.runner import run_command


class RKHunterPack(Pack):
    name = "rkhunter"
    tier = PackTier.RECOMMENDED
    system_bins = ["rkhunter"]
    min_version = "1.4.6"

    def doctor(self) -> PackStatus:
        path, source = resolve_pack_binary("rkhunter", "rkhunter")
        installed = path is not None
        version = None
        if path:
            try:
                res = run_command([path, "--version"], timeout=30)
                match = re.search(r"([\d.]+)", res.stdout)
                version = match.group(1) if match else "1.4.6"
            except (ValueError, OSError):
                version = "unknown"
        status = self._base_status(installed, version)
        if installed:
            status.details = {"tool_source": source, "binary": path}
        if installed:
            status.message = (
                "Upstream releases are infrequent; run propupd after OS updates. "
                "Never propupd on a suspect system."
            )
        return status

    def update(self) -> tuple[bool, str]:
        res = run_privileged(["rkhunter", "--update"], timeout=600)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def propupd(self) -> tuple[bool, str]:
        res = run_privileged(["rkhunter", "--propupd"], timeout=600)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def versioncheck(self) -> tuple[bool, str]:
        path, _ = resolve_pack_binary("rkhunter", "rkhunter")
        if not path:
            return False, "rkhunter not installed"
        res = run_privileged([path, "--versioncheck"], timeout=600)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def scan(self, skip_keypress: bool = True) -> tuple[bool, str]:
        path, _ = resolve_pack_binary("rkhunter", "rkhunter")
        if not path:
            return False, "rkhunter not installed"
        # Best-effort: sync DISABLE_TESTS overlay before check (may require polkit).
        ensure_disable_tests_overlay()
        argv = [path, "--check", "--sk", "--rwo"] if skip_keypress else [path, "--check"]
        res = run_privileged(argv, timeout=7200)
        # --rwo warnings go to stdout via display(). Child-tool noise (egrep
        # obsolescent, grep stray \) lands on stderr — do not feed that to parse.
        output = res.stdout or ""
        if res.returncode != 0 and not output.strip() and (res.stderr or "").strip():
            output = res.stderr
        return res.returncode == 0, output

    def parse_findings(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped.startswith("Warning:"):
                continue
            lower = stripped.lower()
            # Progress / responsibility boilerplate still prefixed Warning: under --rwo.
            if "checking for prerequisites" in lower:
                continue
            threat_name, severity = self._classify_warning(stripped)
            path = self._extract_path(stripped)
            findings.append(
                Finding(
                    pack=self.name,
                    path=path or "system",
                    threat_name=threat_name,
                    severity=severity,
                    message=stripped,
                    raw_line=line,
                )
            )
        return findings

    @staticmethod
    def _classify_warning(line: str) -> tuple[str, FindingSeverity]:
        """Map a real rkhunter Warning: line to threat category + severity."""
        lower = line.lower()
        if "propupd" in lower or "property file updates" in lower:
            return "rkhunter-advisory", FindingSeverity.INFO
        if "ssh configuration option" in lower:
            return "rkhunter-ssh", FindingSeverity.LOW
        if "hidden file found" in lower or "hidden directory found" in lower:
            return "rkhunter-hidden", FindingSeverity.LOW
        if "replaced by a script" in lower or "has been replaced" in lower:
            return "rkhunter-script-replacement", FindingSeverity.LOW
        if "rootkit" in lower or "trojan" in lower:
            return "rkhunter-rootkit", FindingSeverity.HIGH
        return "rkhunter-warning", FindingSeverity.MEDIUM

    @staticmethod
    def _extract_path(line: str) -> str | None:
        """Pull a filesystem path from common rkhunter warning formats."""
        # Hidden file/directory found: /path: …
        match = re.search(
            r"Hidden (?:file|directory) found:\s+(\S+?)(?::|\s|$)",
            line,
            re.IGNORECASE,
        )
        if match:
            candidate = match.group(1).rstrip(":")
            if candidate.startswith("/"):
                return candidate
        # The command '/usr/bin/egrep' has been replaced…
        match = re.search(r"The command '([^']+)'", line)
        if match and match.group(1).startswith("/"):
            return match.group(1)
        return None

    def scan_paths(
        self,
        paths: list[str],
        backend: str = "auto",
        profile: str = "quick",
    ) -> list[Finding]:
        _ = (paths, backend, profile)
        ok, output = self.scan()
        if not ok and "Warning" not in output:
            raise RuntimeError(output[:500])
        return self.parse_findings(output)
