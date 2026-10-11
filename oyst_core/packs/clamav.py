"""ClamAV pack."""

from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Callable
from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config
from oyst_core.models import (
    Finding,
    FindingSeverity,
    PackStatus,
    PackTier,
    PartialScanError,
    ScanProfile,
)
from oyst_core.packs.base import Pack, detect_distro_family, resolve_pack_binary
from oyst_core.packs.clamav_version import security_advisory
from oyst_core.packs.clamd_client import (
    CLAMD_SOCKETS,
    clamd_ping,
    clamdscan_argv,
    discover_endpoint,
)
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.helper_clamd_unit import host_daily_signatures_present
from oyst_core.privileged.runner import (
    CommandResult,
    run_command,
    run_command_cancellable,
    version_gte,
)
from oyst_core.privileged.systemctl_route import run_systemctl_helper
from oyst_core.runtime.bundles.clamav import clamav_db_dir, clamscan_database_args
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.scan_excludes import (
    clamav_exclude_dir_regex,
    merged_clamav_exclude_dirs,
    path_under_any,
)

__all__ = ["CLAMD_SOCKETS", "ClamAVPack"]

# Default clamscan limits live in ScanDefaults (config.toml [scan]).

IGNORE_SIGS_FILENAME = "oysterav.ign2"

# clamscan can take hours on a full home scan.
SCAN_TIMEOUT_SEC = 7200


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

    supports_cancel = True

    def _clamd_socket(self) -> str | None:
        configured = discover_endpoint().local_socket
        if configured and Path(configured).exists():
            return configured
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
        if not host_daily_signatures_present():
            return (
                "Virus definitions are missing; update them first "
                "(oyst-cli freshclam update), then start clamd"
            )
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
        unit = self.clamd_unit()
        if action == "start":
            # Signatures + enable --now in one polkit (ConditionPathExistsGlob).
            res = run_privileged_helper(
                "clamd-cocontrol",
                ["enable-stack", f"--clamd-unit={unit}"],
            )
        elif action == "restart":
            res = run_systemctl_helper("restart", unit)
        elif action == "stop":
            res = run_systemctl_helper("stop", unit)
        else:
            res = run_systemctl_helper(action, unit)
        ok = res.returncode == 0
        SecurityAudit().log(
            "clamav.clamd",
            action,
            success=ok,
            data={"unit": unit},
        )
        if ok and action in ("start", "restart", "ensure"):
            if not self.clamd_running():
                if not host_daily_signatures_present():
                    return (
                        False,
                        "Virus definitions are missing; download them with freshclam "
                        f"before starting {unit}",
                    )
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
            full = is_full_mode()
            status.details = {
                "clamd_running": clamd_up,
                "socket": sock,
                "backend": self.resolve_backend("auto"),
                "binary": clamscan_path or "",
                "tool_source": source,
            }
            advisory = security_advisory(version)
            if advisory:
                status.details["advisory"] = advisory
            if self.ignore_sigs_blocked():
                status.details["ignore_sigs_note"] = (
                    "Ignored signatures can't be applied to the system virus definitions "
                    "without admin rights; use full mode to apply them"
                )
            if version and version.startswith("0."):
                status.version_ok = False
                status.message = "ClamAV 0.x is EOL and blocked from signature updates"
            elif advisory:
                status.message = advisory
            elif full and clamd_up:
                status.details["clamd_note"] = (
                    "clamd uses the system's virus definitions; oysterAV scans use its own"
                )
            elif not clamd_up and not full:
                status.message = self._clamd_service_hint()
        return status

    def resolve_backend(self, backend: str = "auto") -> str:
        """Pick clamd only when it answers PING; full mode keeps private signatures."""
        if backend in ("clamd", "clamscan"):
            return backend
        # Full mode: clamd loads the host DB and never sees oysterav.ign2.
        if is_full_mode():
            return "clamscan"
        clamdscan = resolve_pack_binary("clamav", "clamdscan")[0]
        if clamdscan and self.clamd_running() and clamd_ping(clamdscan):
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
                with contextlib.suppress(OSError):
                    target.unlink()
            return None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(cfg.clamav.ignore_sigs) + "\n", encoding="utf-8")
        except OSError:
            # Lite mode: /var/lib/clamav is clamav-owned. Never fail the scan over it.
            return None
        return target

    def ignore_sigs_blocked(self) -> bool:
        """True when ignored signatures are configured but can't be written."""
        if not load_config().clamav.ignore_sigs:
            return False
        target = self.ignore_sigs_path()
        if target.exists():
            return not os.access(target, os.W_OK)
        return not os.access(target.parent, os.W_OK)

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
        # --exclude-dir is a regex: anchor + escape so /opt never hits ~/x/options/.
        for raw in merged_clamav_exclude_dirs():
            expanded = str(Path(raw).expanduser())
            if expanded and Path(expanded).is_absolute():
                argv.append(f"--exclude-dir={clamav_exclude_dir_regex(expanded)}")

    def _append_profile_scan_mode(self, argv: list[str]) -> None:
        """linux-only skips Windows PE scanning for faster desktop clamscan runs."""
        if load_config().scan.clamav_profile == "linux-only":
            argv.append("--scan-pe=no")

    def scan(
        self,
        path: str,
        backend: str = "auto",
        profile: ScanProfile | str = ScanProfile.QUICK,
        should_cancel: Callable[[], bool] | None = None,
    ) -> CommandResult:
        self.ensure_ignore_sigs()
        target = Path(path).expanduser().resolve()
        cmd = self.resolve_backend(backend)
        binary = "clamdscan" if cmd == "clamd" else "clamscan"
        bin_path, _source = resolve_pack_binary("clamav", binary)
        if not bin_path:
            raise FileNotFoundError(f"{binary} not found")
        if cmd == "clamd":
            # clamdscan ignores -r/--database/limits/--exclude-dir (clamd.conf owns them).
            profile_value = profile.value if isinstance(profile, ScanProfile) else str(profile)
            multiscan = profile_value in (ScanProfile.FULL.value, ScanProfile.SUITE.value)
            argv = clamdscan_argv(bin_path, str(target), multiscan=multiscan)
        else:
            argv = [bin_path, "-r", "--stdout", str(target)]
            argv.extend(clamscan_database_args())
            self._append_profile_flags(argv, profile)
            self._append_exclude_dirs(argv)
            self._append_profile_scan_mode(argv)
        return run_command_cancellable(argv, timeout=SCAN_TIMEOUT_SEC, should_cancel=should_cancel)

    def parse_findings(self, result: CommandResult) -> list[Finding]:
        """Parse ``<path>: <threat> FOUND`` lines from clamscan/clamdscan stdout.

        Paths may contain ``:`` (split on the *last* ``": "``) and newlines: a
        filename with an embedded newline prints as orphan line(s) followed by
        the result line, so orphans are re-joined onto the next result line's
        path. Only lines that *end* in `` FOUND`` are detections.
        """
        findings: list[Finding] = []
        pending: list[str] = []
        for line in result.stdout.split("\n"):
            if line.startswith("----------- SCAN SUMMARY"):
                break
            head, sep, status = line.rpartition(": ")
            if not sep or not head:
                if line:
                    pending.append(line)
                continue
            fpath = "\n".join([*pending, head])
            pending = []
            if not status.endswith(" FOUND"):
                continue
            threat = status[: -len(" FOUND")].strip()
            findings.append(
                Finding(
                    pack=self.name,
                    path=fpath,
                    threat_name=threat or "unknown",
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
        profile: ScanProfile | str = ScanProfile.QUICK,
        should_cancel: Callable[[], bool] | None = None,
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        failures: list[str] = []
        resolved = self.resolve_backend(backend)
        # clamd ignores --exclude-dir: drop hits under excluded dirs (e.g. the vault).
        excluded = (
            [str(Path(d).expanduser()) for d in merged_clamav_exclude_dirs()]
            if resolved == "clamd"
            else []
        )
        for p in paths:
            try:
                res = self.scan(p, backend=resolved, profile=profile, should_cancel=should_cancel)
            except (FileNotFoundError, OSError) as exc:
                raise RuntimeError(str(exc)) from exc
            found = self.parse_findings(res)
            all_findings.extend(f for f in found if not path_under_any(f.path, excluded))
            if res.stopped == "cancel":
                raise PartialScanError("scan stopped; results may be incomplete", all_findings)
            if res.stopped == "timeout":
                failures.append(f"{p}: timed out after {SCAN_TIMEOUT_SEC // 60} minutes")
                continue
            # clamscan/clamdscan: 0 clean, 1 virus found, >=2 error (DB load failure,
            # unreadable files, bad option). An error is never a clean result.
            if res.returncode not in (0, 1):
                detail = (res.stderr or "").strip().splitlines() or [
                    ln for ln in res.stdout.splitlines() if ln.startswith("ERROR:")
                ]
                failures.append(
                    f"{p}: exit {res.returncode}" + (f" ({detail[-1][:200]})" if detail else "")
                )
        if failures:
            raise PartialScanError("clamav reported errors: " + "; ".join(failures), all_findings)
        return all_findings
