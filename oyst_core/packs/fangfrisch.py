"""Fangfrisch unofficial ClamAV signature pack (optional)."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from oyst_core.config import data_dir, load_config
from oyst_core.models import PackStatus, PackTier
from oyst_core.packs.base import Pack
from oyst_core.privileged.runner import run_command
from oyst_core.runtime.bundles.clamav import clamav_db_dir
from oyst_core.runtime.manifest import is_full_mode
from oyst_core.runtime.resolver import resolve_pack_tool


class FangfrischPack(Pack):
    """Refresh unofficial ClamAV DBs after freshclam (does not replace official CVD)."""

    name = "fangfrisch"
    tier = PackTier.OPTIONAL
    system_bins = ["fangfrisch"]

    def _binary(self) -> str | None:
        return resolve_pack_tool(self.name).path

    def _conf_path(self) -> Path:
        return data_dir() / "fangfrisch" / "fangfrisch.conf"

    def _sqlite_path(self) -> Path:
        return data_dir() / "fangfrisch" / "db.sqlite"

    def _local_directory(self) -> Path:
        if is_full_mode():
            return clamav_db_dir()
        system = Path("/var/lib/clamav")
        if system.is_dir():
            return system
        return clamav_db_dir()

    def _detect_version(self, path: str | None) -> str | None:
        if not path:
            return None
        # Prefer the venv interpreter from the script shebang (private runtime).
        try:
            first = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()[0]
            if first.startswith("#!"):
                py = first[2:].strip()
                probe = "from importlib.metadata import version; print(version('fangfrisch'))"
                res = run_command([py, "-c", probe], timeout=15)
                ver = (res.stdout or "").strip()
                if res.returncode == 0 and ver:
                    return ver
        except (ValueError, OSError, IndexError):
            pass
        # Fallback: dist-info directory next to a site-packages install.
        try:
            binary = Path(path).resolve()
            for parent in binary.parents:
                matches = list(parent.glob("**/fangfrisch-*.dist-info"))
                if matches:
                    match = re.search(r"fangfrisch-([^-]+)\.dist-info$", matches[0].name)
                    if match:
                        return match.group(1)
        except OSError:
            pass
        return None

    def doctor(self) -> PackStatus:
        resolved = resolve_pack_tool(self.name)
        installed = resolved.path is not None
        version = self._detect_version(resolved.path) if installed else None
        status = self._base_status(installed, version)
        conf = self._conf_path()
        db_dir = self._local_directory()
        yara_count = len(list(db_dir.glob("*.yar"))) + len(list(db_dir.glob("*.yara")))
        status.details = {
            "binary": resolved.path or "",
            "source": resolved.source,
            "conf": str(conf) if conf.is_file() else "",
            "local_directory": str(db_dir),
            "yara_rules_in_db": yara_count,
        }
        providers = load_config().fangfrisch.providers
        status.details["providers"] = providers
        if installed and not conf.is_file():
            status.message = "Run oyst-cli fangfrisch ensure-config then initdb"
        elif installed and yara_count:
            status.message = f"{yara_count} user/provider YARA rule file(s) in ClamAV DB dir"
        return status

    def ensure_config(self, *, force: bool = False) -> tuple[bool, str]:
        """Write oysterAV-managed fangfrisch.conf pointing at the ClamAV DB directory."""
        conf = self._conf_path()
        if conf.is_file() and not force:
            return True, f"exists (use --force to rewrite): {conf}"
        conf.parent.mkdir(parents=True, exist_ok=True)
        db_dir = self._local_directory()
        db_dir.mkdir(parents=True, exist_ok=True)
        sqlite = self._sqlite_path()
        providers = load_config().fangfrisch.providers
        sections = [
            textwrap.dedent(
                f"""\
                # Managed by oysterAV — unofficial signatures complement freshclam CVD.
                [DEFAULT]
                db_url = sqlite:///{sqlite}
                local_directory = {db_dir}
                integrity_check = sha256
                log_level = WARNING
                enabled = no
                """,
            ).rstrip(),
        ]
        for name in providers:
            sections.append(f"[{name}]\nenabled = yes")
        conf.write_text("\n\n".join(sections) + "\n", encoding="utf-8")
        enabled = ", ".join(providers) if providers else "(none)"
        return True, f"Wrote {conf} (local_directory={db_dir}; providers={enabled})"

    def initdb(self, *, force: bool = False) -> tuple[bool, str]:
        path = self._binary()
        if not path:
            return False, "fangfrisch not installed"
        conf = self._conf_path()
        if not conf.is_file():
            ok, msg = self.ensure_config()
            if not ok:
                return False, msg
        argv = [path, "--conf", str(self._conf_path())]
        if force:
            argv.append("--force")
        argv.append("initdb")
        res = run_command(argv, timeout=120)
        return res.returncode == 0, (res.stdout or res.stderr or "").strip() or (
            "ok" if res.returncode == 0 else "initdb failed"
        )

    def refresh(self) -> tuple[bool, str]:
        """Download/update unofficial signatures into the ClamAV DB directory."""
        path = self._binary()
        if not path:
            return False, "fangfrisch not installed"
        conf = self._conf_path()
        if not conf.is_file():
            self.ensure_config()
            ok, msg = self.initdb()
            if not ok:
                return False, f"initdb required before refresh: {msg}"
        res = run_command(
            [path, "--conf", str(self._conf_path()), "refresh"],
            timeout=1800,
        )
        ok = res.returncode == 0
        return ok, (res.stdout or res.stderr or "").strip() or ("ok" if ok else "refresh failed")
