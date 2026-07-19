"""Lynis security audit pack."""

from __future__ import annotations

import json
import re
from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import data_dir
from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.privileged.helper import run_privileged
from oyst_core.privileged.runner import run_command, which

LYNIS_REPORT = data_dir() / "lynis-last.json"
BUNDLED_PROFILES = Path(__file__).resolve().parents[2] / "packaging" / "lynis"


class LynisPack(Pack):
    name = "lynis"
    tier = PackTier.RECOMMENDED
    system_bins = ["lynis"]
    min_version = "3.1.0"

    def doctor(self) -> PackStatus:
        path, source = resolve_pack_binary("lynis", "lynis")
        installed = path is not None
        version = self._read_version(path) if path else None
        status = self._base_status(installed, version)
        if installed:
            status.details = {"tool_source": source, "binary": path}
        return status

    @staticmethod
    def _read_version(path: str) -> str | None:
        """Parse PROGRAM_VERSION from the lynis script (avoids slow `lynis show version`)."""
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        match = re.search(r'^\s*PROGRAM_VERSION="([\d.]+)"', text, re.MULTILINE)
        if match:
            return match.group(1)
        try:
            res = run_command([path, "show", "version"], timeout=30)
            match = re.search(r"([\d.]+)", res.stdout)
            return match.group(1) if match else None
        except (ValueError, OSError):
            return None

    def list_profiles(self) -> list[dict[str, str]]:
        profiles: list[dict[str, str]] = []
        if BUNDLED_PROFILES.is_dir():
            for prf in sorted(BUNDLED_PROFILES.glob("*.prf")):
                profiles.append({"name": prf.stem, "path": str(prf), "source": "bundled"})
        etc = Path("/etc/lynis")
        if etc.is_dir():
            for prf in sorted(etc.glob("*.prf")):
                profiles.append({"name": prf.stem, "path": str(prf), "source": "system"})
        return profiles

    def resolve_profile(self, profile: str | None, scope: str) -> str | None:
        if profile:
            path = Path(profile).expanduser()
            if path.is_file():
                return str(path)
            bundled = BUNDLED_PROFILES / f"{profile}.prf"
            if bundled.is_file():
                return str(bundled)
            system = Path("/etc/lynis") / f"{profile}.prf"
            if system.is_file():
                return str(system)
            raise FileNotFoundError(f"profile not found: {profile}")
        if scope == "container-host":
            bundled = BUNDLED_PROFILES / "container-host.prf"
            if bundled.is_file():
                return str(bundled)
        return None

    def audit(
        self,
        *,
        profile: str | None = None,
        scope: str = "host",
        quick: bool = True,
    ) -> tuple[bool, str, int | None]:
        path, _ = resolve_pack_binary("lynis", "lynis")
        if not path:
            return False, "lynis not installed", None
        argv = [path, "audit", "system", "--no-colors"]
        if quick:
            argv.append("--quick")
        profile_path = self.resolve_profile(profile, scope)
        if profile_path:
            argv.extend(["--profile", profile_path])
        res = run_privileged(argv, timeout=7200)
        output = res.stdout + res.stderr
        score = self._parse_hardening_index(output)
        self._cache_report(output, score, profile=profile, scope=scope)
        SecurityAudit().log(
            "lynis.audit",
            scope,
            success=res.returncode == 0,
            data={"profile": profile_path, "hardening_index": score},
        )
        return res.returncode == 0, output, score

    def audit_container(
        self,
        container_id: str,
        *,
        quick: bool = True,
    ) -> tuple[bool, str, int | None]:
        if not which("docker"):
            return False, "docker not installed", None
        path, _ = resolve_pack_binary("lynis", "lynis")
        if not path:
            return False, "lynis not installed", None
        argv = [
            "docker",
            "exec",
            container_id,
            "lynis",
            "audit",
            "system",
            "--no-colors",
        ]
        if quick:
            argv.append("--quick")
        res = run_command(argv, timeout=7200)
        output = res.stdout + res.stderr
        score = self._parse_hardening_index(output)
        return res.returncode == 0, output, score

    def _parse_hardening_index(self, output: str) -> int | None:
        match = re.search(r"Hardening index\s*:\s*(\d+)", output)
        return int(match.group(1)) if match else None

    def _cache_report(
        self,
        output: str,
        score: int | None,
        *,
        profile: str | None,
        scope: str,
    ) -> None:
        LYNIS_REPORT.write_text(
            json.dumps(
                {
                    "hardening_index": score,
                    "output": output[-20000:],
                    "profile": profile,
                    "scope": scope,
                },
            ),
            encoding="utf-8",
        )

    def status(self) -> dict[str, object]:
        if not LYNIS_REPORT.exists():
            return {"hardening_index": None, "last_run": None, "scope": None, "profile": None}
        data = json.loads(LYNIS_REPORT.read_text(encoding="utf-8"))
        return {
            "hardening_index": data.get("hardening_index"),
            "last_run": LYNIS_REPORT.stat().st_mtime,
            "scope": data.get("scope"),
            "profile": data.get("profile"),
        }

    def export_json(self, dest: Path) -> None:
        if LYNIS_REPORT.exists():
            dest.write_text(LYNIS_REPORT.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            dest.write_text("{}", encoding="utf-8")

    def export_html(self, dest: Path) -> None:
        data = self.status()
        score = data.get("hardening_index", "N/A")
        html = f"""<!DOCTYPE html><html><head><title>Lynis Report</title></head>
<body><h1>oysterAV Lynis Report</h1><p>Hardening index: {score}</p></body></html>"""
        dest.write_text(html, encoding="utf-8")
