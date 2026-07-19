"""ClamAV pack."""

from __future__ import annotations

import re
from pathlib import Path

from oyst_core.config import load_config
from oyst_core.models import Finding, FindingSeverity, PackStatus, PackTier, ScanProfile
from oyst_core.packs.base import Pack, detect_distro_family, resolve_pack_binary
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import CommandResult, run_command, version_gte
from oyst_core.runtime.bundles.clamav import clamav_db_dir, clamscan_database_args
from oyst_core.runtime.manifest import is_full_mode

CLAMD_SOCKETS = [
    "/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/var/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.sock",
]

# Default clamscan limits live in ScanDefaults (config.toml [scan]).

IGNORE_SIGS_FILENAME = "oysterav.ign2"


class ClamAVPack(Pack):
    name = "clamav"
    tier = PackTier.REQUIRED
    system_bins = ["clamscan", "clamdscan"]
    min_version = "1.4.0"

    def _detect_version(self) -> str | None:
        for cmd in ("clamscan", "clamdscan"):
            path, _source = resolve_pack_binary("clamav", cmd)
            if not path:
                continue
            try:
                res = run_command([path, "--version"], timeout=30)
                match = re.search(r"ClamAV\s+([\d.]+)", res.stdout)
                if match:
                    return match.group(1)
            except (ValueError, OSError):
                continue
        return None

    def _clamd_socket(self) -> str | None:
        for sock in CLAMD_SOCKETS:
            if Path(sock).exists():
                return sock
        return None

    def clamd_running(self) -> bool:
        try:
            res = run_command(["pgrep", "-x", "clamd"], timeout=10)
            return res.returncode == 0
        except (ValueError, OSError):
            return False

    def _clamd_service_hint(self) -> str:
        unit = self.clamd_unit()
        return f"Enable clamd for faster scans: sudo systemctl enable --now {unit}"

    def clamd_unit(self) -> str:
        family = detect_distro_family()
        if family == "fedora":
            return "clamd@scan"
        return "clamav-daemon"

    def clamd_status(self) -> dict[str, object]:
        unit = self.clamd_unit()
        active = False
        enabled = False
        try:
            active_res = run_command(["systemctl", "is-active", unit], timeout=15)
            active = active_res.stdout.strip() == "active"
            enabled_res = run_command(["systemctl", "is-enabled", unit], timeout=15)
            enabled = enabled_res.stdout.strip() in ("enabled", "enabled-runtime")
        except (ValueError, OSError):
            pass
        return {
            "unit": unit,
            "active": active,
            "enabled": enabled,
            "running": self.clamd_running(),
            "socket": self._clamd_socket(),
        }

    def _clamd_action(self, action: str) -> tuple[bool, str]:
        from oyst_core.audit import SecurityAudit

        unit = self.clamd_unit()
        helper_action = "enable-now" if action == "start" else action
        if action == "restart":
            helper_action = "restart"
        elif action == "stop":
            helper_action = "stop"
        elif action == "start":
            helper_action = "enable-now"
        res = run_privileged_helper("systemctl", [helper_action, unit])
        ok = res.returncode == 0
        SecurityAudit().log(
            "clamav.clamd",
            action,
            success=ok,
            data={"unit": unit},
        )
        if ok and action in ("start", "restart", "ensure"):
            if not self.clamd_running():
                return False, f"{unit} started but clamd process not detected"
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return ok, msg

    def clamd_start(self) -> tuple[bool, str]:
        return self._clamd_action("start")

    def clamd_stop(self) -> tuple[bool, str]:
        return self._clamd_action("stop")

    def clamd_restart(self) -> tuple[bool, str]:
        return self._clamd_action("restart")

    def clamd_ensure(self) -> tuple[bool, str]:
        status = self.clamd_status()
        if status.get("running"):
            return True, "clamd already running"
        return self._clamd_action("start")

    def doctor(self) -> PackStatus:
        version = self._detect_version()
        clamscan_path, source = resolve_pack_binary("clamav", "clamscan")
        installed = version is not None or clamscan_path is not None
        status = self._base_status(installed, version)
        if installed:
            status.details = status.details or {}
            status.details["tool_source"] = source
        if installed and version and not version_gte(version, self.min_version or "0"):
            status.version_ok = False
            status.message = f"ClamAV {version} is below minimum {self.min_version}"
        elif installed:
            sock = self._clamd_socket()
            clamd_up = self.clamd_running()
            status.details = {
                "clamd_running": clamd_up,
                "socket": sock,
                "backend": "clamd" if clamd_up else "clamscan",
                "binary": clamscan_path or "",
                "tool_source": source,
            }
            if version and version.startswith("0."):
                status.version_ok = False
                status.message = "ClamAV 0.x is EOL and blocked from signature updates"
            elif not clamd_up:
                status.message = self._clamd_service_hint()
        return status

    def resolve_backend(self, backend: str = "auto") -> str:
        if backend in ("clamd", "clamscan"):
            return backend
        if self.clamd_running() and resolve_pack_binary("clamav", "clamdscan")[0]:
            return "clamd"
        return "clamscan"

    def ignore_sigs_path(self) -> Path:
        """Path for the managed oysterAV signature ignore file."""
        if is_full_mode():
            return clamav_db_dir() / IGNORE_SIGS_FILENAME
        system = Path("/var/lib/clamav")
        if system.is_dir():
            return system / IGNORE_SIGS_FILENAME
        return clamav_db_dir() / IGNORE_SIGS_FILENAME

    def ensure_ignore_sigs(self) -> Path | None:
        """Write or remove oysterav.ign2 from clamav.ignore_sigs config."""
        cfg = load_config()
        target = self.ignore_sigs_path()
        if not cfg.clamav.ignore_sigs:
            if target.is_file():
                try:
                    target.unlink()
                except OSError:
                    pass
            return None
        target.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(cfg.clamav.ignore_sigs) + "\n"
        target.write_text(body, encoding="utf-8")
        return target

    def scan_limit_flags(self, profile: ScanProfile | str) -> list[str]:
        """Build clamscan size/recursion limits from config."""
        cfg = load_config()
        profile_value = profile.value if isinstance(profile, ScanProfile) else str(profile)
        apply = cfg.scan.apply_limits_to
        if apply == "quick" and profile_value != ScanProfile.QUICK.value:
            return []
        return [
            f"--max-filesize={cfg.scan.max_filesize}",
            f"--max-recursion={cfg.scan.max_recursion}",
            f"--max-files={cfg.scan.max_files}",
        ]

    def _append_profile_flags(self, argv: list[str], profile: ScanProfile | str) -> None:
        argv.extend(self.scan_limit_flags(profile))

    def _append_exclude_dirs(self, argv: list[str]) -> None:
        for raw in load_config().scan.exclude_dirs:
            expanded = str(Path(raw).expanduser())
            if expanded:
                argv.append(f"--exclude-dir={expanded}")

    def _append_profile_scan_mode(self, argv: list[str]) -> None:
        """linux-only skips Windows PE scanning for faster desktop clamscan runs."""
        if load_config().scan.clamav_profile == "linux-only":
            argv.append("--scan-pe=no")

    def scan(
        self,
        path: str,
        backend: str = "auto",
        profile: ScanProfile | str = ScanProfile.QUICK,
    ) -> CommandResult:
        self.ensure_ignore_sigs()
        target = Path(path).expanduser().resolve()
        cmd = self.resolve_backend(backend)
        binary = "clamdscan" if cmd == "clamd" else "clamscan"
        bin_path, _source = resolve_pack_binary("clamav", binary)
        if not bin_path:
            raise FileNotFoundError(f"{binary} not found")
        argv = [bin_path, "-r", "--stdout", str(target)]
        argv.extend(clamscan_database_args())
        if cmd == "clamd":
            sock = self._clamd_socket()
            if sock:
                argv[1:1] = ["--config-file=/dev/null"]
        if cmd == "clamscan":
            self._append_profile_flags(argv, profile)
            self._append_exclude_dirs(argv)
            self._append_profile_scan_mode(argv)
        return run_command(argv, timeout=7200)

    def parse_findings(self, result: CommandResult) -> list[Finding]:
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            if "FOUND" in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    fpath = parts[0].strip()
                    threat = (
                        parts[1].replace("FOUND", "").strip()
                        if len(parts) == 2
                        else parts[2].strip()
                    )
                    findings.append(
                        Finding(
                            pack=self.name,
                            path=fpath,
                            threat_name=threat or "unknown",
                            severity=FindingSeverity.HIGH,
                            message=line.strip() or f"{threat} in {fpath}",
                            raw_line=line,
                        )
                    )
        return findings

    def scan_paths(
        self,
        paths: list[str],
        backend: str = "auto",
        profile: ScanProfile | str = ScanProfile.QUICK,
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        for p in paths:
            try:
                res = self.scan(p, backend=backend, profile=profile)
                all_findings.extend(self.parse_findings(res))
            except (FileNotFoundError, OSError) as exc:
                raise RuntimeError(str(exc)) from exc
        return all_findings
