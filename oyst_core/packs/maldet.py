"""Linux Malware Detect (maldet) optional pack."""

from __future__ import annotations

import re
from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config, save_config
from oyst_core.models import Finding, FindingSeverity, PackStatus, PackTier
from oyst_core.pack_sources import configure_maldet_clamav, ensure_maldet_pub_paths
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import run_command, which
from oyst_core.runtime.manifest import is_full_mode, runtime_maldet_prefix

MALDET_PATHS = ["/usr/local/sbin/maldet", "/usr/sbin/maldet", "/usr/bin/maldet"]
MALDET_CONF = Path("/usr/local/maldetect/conf.maldet")
MALDET_EVENT_LOG = Path("/usr/local/maldetect/logs/event_log")
INOTIFY_WATCHES = Path("/proc/sys/fs/inotify/max_user_watches")


class MaldetPack(Pack):
    name = "maldet"
    tier = PackTier.OPTIONAL
    system_bins = ["maldet"]
    min_version = "2.0.0"

    def _binary(self) -> str | None:
        path, _ = resolve_pack_binary("maldet", "maldet")
        if path:
            return path
        for p in MALDET_PATHS:
            if Path(p).exists():
                return p
        return None

    def doctor(self) -> PackStatus:
        binary = self._binary()
        installed = binary is not None
        _path, source = resolve_pack_binary("maldet", "maldet")
        version = None
        if binary:
            try:
                res = run_command([binary, "--version"], timeout=30)
                match = re.search(r"([\d.]+)", res.stdout + res.stderr)
                version = match.group(1) if match else None
            except (ValueError, OSError):
                version = None
        status = self._base_status(installed, version)
        if not installed:
            status.install_hint = "Install LMD from https://rfxn.com/projects/linux-malware-detect"
        monitor = self.monitor_status()
        clam_path, _ = resolve_pack_binary("clamav", "clamscan")
        clamav_ok = clam_path is not None
        # Side-effect config writes belong in enable/install paths, not doctor().
        status.details = {
            "binary": binary,
            "install_root": str(runtime_maldet_prefix()),
            "tool_source": source if binary else "missing",
            "monitor": monitor,
            "clamav_integration": clamav_ok,
            "quarantine_note": (
                "Use oysterAV quarantine for findings; maldet's local quarantine is secondary"
            ),
        }
        messages: list[str] = []
        if monitor.get("enabled") and monitor.get("inotify_tools") is False:
            messages.append("inotify-tools required for monitor mode")
        if installed and not clamav_ok:
            messages.append("Install clamav to enable layered maldet+ClamAV scanning")
        if messages:
            status.message = "; ".join(messages)
        return status

    def ensure_clamav_integration(self) -> bool:
        """Tune maldet conf for oysterAV (ClamAV layering + non-root access)."""
        prefix = runtime_maldet_prefix() if is_full_mode() else None
        if prefix is not None and not (prefix / "conf.maldet").is_file():
            prefix = None
        changed = configure_maldet_clamav(prefix)
        binary = self._binary()
        if binary:
            ensure_maldet_pub_paths(binary)
        return changed

    def update_sigs(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        # Runtime/desktop installs need scan_user_access + pub paths for non-root -u.
        self.ensure_clamav_integration()
        res = run_command([binary, "-u"], timeout=1800)
        out = (res.stdout or res.stderr or "").strip()
        return res.returncode == 0, out

    def list_scans(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        res = run_command([binary, "-l"], timeout=120)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def quarantine_list(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        res = run_command([binary, "-q"], timeout=120)
        return res.returncode == 0, (res.stdout or res.stderr).strip()

    def scan(self, path: str) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        res = run_command([binary, "-a", str(Path(path).expanduser())], timeout=7200)
        return res.returncode == 0, res.stdout + res.stderr

    def parse_findings(self, output: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lowered = stripped.lower()
            # Version / banner lines contain "malware" but are not hits.
            if re.match(r"^linux malware detect\b", lowered):
                continue
            if "maldetect v" in lowered and "/" not in stripped:
                continue
            has_hit_keyword = "hit" in lowered or "found" in lowered or "malware" in lowered
            if not has_hit_keyword:
                continue
            path = self._extract_path(stripped)
            # Require a filesystem path so banners/summaries without paths are dropped.
            if not path or not (path.startswith("/") or path.startswith("~")):
                continue
            findings.append(
                Finding(
                    pack=self.name,
                    path=path,
                    threat_name="maldet-detection",
                    severity=FindingSeverity.HIGH,
                    message=f"maldet hit: {path}",
                    raw_line=line,
                ),
            )
        return findings

    @staticmethod
    def _extract_path(line: str) -> str | None:
        """Best-effort path extraction so oysterAV quarantine can act on hits."""
        tokens = line.split()
        for token in reversed(tokens):
            cleaned = token.strip("\",'")
            if cleaned.startswith("/") or cleaned.startswith("~"):
                expanded = str(Path(cleaned).expanduser())
                if Path(expanded).exists() or "/" in cleaned:
                    return expanded
        return None

    def scan_paths(
        self,
        paths: list[str],
        backend: str = "auto",
        profile: str = "quick",
    ) -> list[Finding]:
        _ = (backend, profile)
        all_findings: list[Finding] = []
        for p in paths:
            ok, output = self.scan(p)
            if not ok and "not installed" in output:
                continue
            all_findings.extend(self.parse_findings(output))
        return all_findings

    def _inotify_watches(self) -> int | None:
        try:
            return int(INOTIFY_WATCHES.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None

    def monitor_status(self) -> dict[str, object]:
        cfg = load_config()
        running = False
        try:
            res = run_command(["systemctl", "is-active", "maldet"], timeout=15)
            running = res.stdout.strip() == "active"
        except (ValueError, OSError):
            pass
        overlaps = self._clamonacc_overlaps(cfg.maldet_monitor.paths)
        return {
            "enabled": cfg.maldet_monitor.enabled,
            "mode": cfg.maldet_monitor.mode,
            "paths": cfg.maldet_monitor.paths,
            "running": running,
            "inotify_tools": which("inotifywait") is not None,
            "max_user_watches": self._inotify_watches(),
            "clamonacc_overlaps": overlaps,
        }

    def _clamonacc_overlaps(self, paths: list[str]) -> list[str]:
        cfg = load_config()
        overlaps: list[str] = []
        expanded = [str(Path(p).expanduser()) for p in paths]
        for cp in cfg.clamonacc.paths:
            cpath = str(Path(cp).expanduser())
            for mp in expanded:
                if cpath == mp or cpath.startswith(mp + "/") or mp.startswith(cpath + "/"):
                    overlaps.append(mp)
        return overlaps

    def _monitor_mode_value(self) -> str:
        cfg = load_config()
        if cfg.maldet_monitor.mode == "paths":
            if not cfg.maldet_monitor.paths:
                raise ValueError("maldet_monitor.paths is empty")
            return ",".join(str(Path(p).expanduser()) for p in cfg.maldet_monitor.paths)
        return "users"

    def monitor_start(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        if not which("inotifywait"):
            return False, "inotify-tools not installed (required for monitor mode)"
        watches = self._inotify_watches()
        if watches is not None and watches < 8192:
            return False, f"inotify max_user_watches too low ({watches}); raise before starting"
        overlaps = self._clamonacc_overlaps(load_config().maldet_monitor.paths)
        if overlaps:
            return False, f"paths overlap clamonacc watches: {', '.join(overlaps)}"
        mode = self._monitor_mode_value()
        res = run_privileged_helper("maldet-config", ["start-monitor", mode])
        ok = res.returncode == 0
        if ok:
            cfg = load_config()
            cfg.maldet_monitor.enabled = True
            save_config(cfg)
        SecurityAudit().log("maldet.monitor", "start", success=ok, data={"mode": mode})
        msg = (res.stdout or res.stderr or "").strip() or ("ok" if ok else "failed")
        return ok, msg

    def monitor_stop(self) -> tuple[bool, str]:
        binary = self._binary()
        if not binary:
            return False, "maldet not installed"
        kill_res = run_command([binary, "-k"], timeout=60)
        svc = run_privileged_helper("systemctl", ["stop", "maldet"])
        ok = svc.returncode == 0 or kill_res.returncode == 0
        cfg = load_config()
        cfg.maldet_monitor.enabled = False
        save_config(cfg)
        SecurityAudit().log("maldet.monitor", "stop", success=ok)
        return ok, "monitor stopped" if ok else (svc.stderr or "stop failed")

    def list_monitor_paths(self) -> list[str]:
        return load_config().maldet_monitor.paths

    def add_monitor_path(self, path: str) -> None:
        cfg = load_config()
        expanded = str(Path(path).expanduser())
        if expanded not in cfg.maldet_monitor.paths:
            cfg.maldet_monitor.paths.append(expanded)
        cfg.maldet_monitor.mode = "paths"
        save_config(cfg)

    def remove_monitor_path(self, path: str) -> bool:
        cfg = load_config()
        expanded = str(Path(path).expanduser())
        before = list(cfg.maldet_monitor.paths)
        cfg.maldet_monitor.paths = [p for p in before if p != expanded]
        if len(cfg.maldet_monitor.paths) == len(before):
            return False
        save_config(cfg)
        return True

    def tail_events(self, lines: int = 20) -> tuple[bool, str]:
        if not MALDET_EVENT_LOG.is_file():
            return False, "event log not found"
        content = MALDET_EVENT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = content[-lines:] if lines > 0 else content
        return True, "\n".join(tail)
