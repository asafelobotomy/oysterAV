"""clamonacc on-access protection pack."""

from __future__ import annotations

import re
from pathlib import Path

from oyst_core.config import data_dir, load_config, save_config, set_config_value
from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack, resolve_pack_binary
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamd_onaccess import probe_onaccess_prevention
from oyst_core.privileged.helper import run_privileged, run_privileged_helper
from oyst_core.privileged.runner import run_command


class ClamonaccPack(Pack):
    name = "clamonacc"
    tier = PackTier.RECOMMENDED
    system_bins = ["clamonacc"]
    min_version = "1.4.0"

    def _binary(self) -> tuple[str | None, str]:
        return resolve_pack_binary("clamonacc", "clamonacc")

    def _detect_version(self, path: str | None) -> str | None:
        # clamonacc --version may fail without fanotify privileges; prefer clamscan.
        clam_version = ClamAVPack()._detect_version()
        if clam_version:
            return clam_version
        if not path:
            return None
        try:
            res = run_command([path, "--version"], timeout=30)
            match = re.search(r"ClamAV\s+([\d.]+)", res.stdout + res.stderr)
            if match:
                return match.group(1)
        except (ValueError, OSError):
            pass
        return None

    def doctor(self) -> PackStatus:
        path, source = self._binary()
        installed = path is not None
        clam = ClamAVPack()
        clamd_ok = clam.clamd_running()
        version = self._detect_version(path) if installed else None
        status = self._base_status(installed, version)
        if installed and not clamd_ok:
            status.message = "clamonacc requires clamd to be running"
        status.details = {
            "clamd_running": clamd_ok,
            "running": self.is_running(),
            "tool_source": source if installed else "missing",
            "binary": path,
            "systemd_unit": self._systemd_unit(),
        }
        cfg = load_config()
        status.details["configured_paths"] = cfg.clamonacc.paths
        status.details["exclude_paths"] = cfg.clamonacc.exclude_paths
        status.details["prevention_requested"] = cfg.clamonacc.prevention
        unit = self._systemd_unit()
        status.details["uses_distro_unit"] = unit is not None
        onaccess = probe_onaccess_prevention()
        status.details["onaccess"] = onaccess
        if cfg.clamonacc.prevention:
            if onaccess.get("prevention_enforced"):
                status.message = f"prevention enforced by host conf ({onaccess.get('conf_path')})"
            elif unit:
                status.message = (
                    "prevention=true but host OnAccessPrevention not blocking "
                    f"(distro unit {unit}; classification={onaccess.get('classification')})"
                )
            else:
                status.message = (
                    "prevention=true but host OnAccessPrevention not blocking "
                    f"(process-mode --fdpass; classification={onaccess.get('classification')})"
                )
        return status

    def _systemd_unit(self) -> str | None:
        """Return distro unit name when clamav-clamonacc is available."""
        for unit in ("clamav-clamonacc.service", "clamav-clamonacc"):
            try:
                res = run_command(["systemctl", "list-unit-files", unit], timeout=15)
            except (ValueError, OSError):
                continue
            if res.returncode != 0:
                continue
            for line in (res.stdout or "").splitlines():
                first = line.split(None, 1)[0] if line.strip() else ""
                if first in ("clamav-clamonacc.service", "clamav-clamonacc"):
                    return "clamav-clamonacc"
        return None

    def is_running(self) -> bool:
        unit = self._systemd_unit()
        if unit:
            try:
                res = run_command(["systemctl", "is-active", unit], timeout=10)
                if res.stdout.strip() == "active":
                    return True
            except (ValueError, OSError):
                pass
        try:
            res = run_command(["pgrep", "-x", "clamonacc"], timeout=10)
            return res.returncode == 0
        except (ValueError, OSError):
            return False

    def _write_path_list(self, filename: str, raw_paths: list[str]) -> Path | None:
        """Write absolute existing paths (never '/') for clamonacc include/exclude lists."""
        paths: list[str] = []
        for raw in raw_paths:
            expanded = Path(raw).expanduser().resolve()
            if str(expanded) == "/":
                continue
            if not expanded.exists():
                continue
            paths.append(str(expanded))
        if not paths:
            return None
        list_path = data_dir() / filename
        list_path.parent.mkdir(parents=True, exist_ok=True)
        list_path.write_text("\n".join(paths) + "\n", encoding="utf-8")
        return list_path

    def _write_include_list(self) -> Path | None:
        """Write oysterAV watch paths for clamonacc --include-list (never '/')."""
        return self._write_path_list("clamonacc-include.list", self.list_paths())

    def _write_exclude_list(self) -> Path | None:
        """Write oysterAV exclude paths for clamonacc --exclude-list."""
        return self._write_path_list(
            "clamonacc-exclude.list",
            load_config().clamonacc.exclude_paths,
        )

    def start(self) -> tuple[bool, str]:
        path, _ = self._binary()
        if not path:
            return False, "clamonacc not installed"
        if self.is_running():
            return True, "already running"

        unit = self._systemd_unit()
        if unit:
            # Distro unit is durable across reboot; OnAccess paths come from clamd.conf.
            res = run_privileged_helper("systemctl", ["enable-now", unit])
            if self.is_running():
                return True, f"started via {unit}"
            return (
                res.returncode == 0,
                (res.stderr or res.stdout or f"failed to start {unit}").strip(),
            )

        # Process mode: detect-only with --fdpass (prevention needs clamd.conf).
        argv = [path, "--foreground", "--fdpass"]
        include = self._write_include_list()
        if include is not None:
            argv.append(f"--include-list={include}")
        exclude = self._write_exclude_list()
        if exclude is not None:
            argv.append(f"--exclude-list={exclude}")
        res = run_privileged(argv, timeout=5)
        if self.is_running():
            return True, "started"
        return res.returncode == 0, res.stderr or res.stdout

    def stop(self) -> tuple[bool, str]:
        unit = self._systemd_unit()
        if unit:
            res = run_privileged_helper("systemctl", ["disable-now", unit])
            if not self.is_running():
                return True, f"stopped via {unit}"
            # Fall through to pkill if unit stop left a process
            _ = res
        try:
            res = run_command(["pkill", "-x", "clamonacc"], timeout=10)
        except ValueError:
            return False, "stop not allowlisted"
        return True, "stopped" if res.returncode in (0, 1) else res.stderr

    def list_paths(self) -> list[str]:
        return load_config().clamonacc.paths

    def add_path(self, path: str) -> None:
        expanded = str(Path(path).expanduser())
        cfg = load_config()
        if expanded not in cfg.clamonacc.paths:
            cfg.clamonacc.paths.append(expanded)
            save_config(cfg)

    def remove_path(self, path: str) -> bool:
        expanded = str(Path(path).expanduser())
        cfg = load_config()
        before = list(cfg.clamonacc.paths)
        cfg.clamonacc.paths = [p for p in before if p != path and p != expanded]
        if len(cfg.clamonacc.paths) == len(before):
            return False
        save_config(cfg)
        return True

    def enable(self) -> tuple[bool, str]:
        set_config_value("clamonacc.enabled", "true")
        clam = ClamAVPack()
        ok, msg = clam.clamd_ensure()
        if not ok:
            return False, msg
        return self.start()

    def disable(self) -> tuple[bool, str]:
        ok, msg = self.stop()
        set_config_value("clamonacc.enabled", "false")
        return ok, msg
