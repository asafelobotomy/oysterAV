"""Config path helpers and TOML load/save."""

from __future__ import annotations

import logging
import os
import tempfile
import time
import tomllib
import warnings
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from oyst_core.config_models import OysterConfig

_log = logging.getLogger(__name__)


def config_dir() -> Path:
    path = Path.home() / ".config" / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def data_dir() -> Path:
    path = Path.home() / ".local" / "share" / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def config_path() -> Path:
    # Resolve via façade so monkeypatches on oyst_core.config.config_dir apply.
    from oyst_core import config as cfg_facade

    return cfg_facade.config_dir() / "config.toml"


def _defaults_toml() -> dict[str, Any]:
    return OysterConfig().model_dump()


def _migrate_raw_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize legacy keys so prefs are not duplicated across sections."""
    runtime = raw.get("runtime")
    scan = raw.get("scan")
    if not isinstance(scan, dict):
        scan = {}
        raw["scan"] = scan
    if isinstance(runtime, dict) and "clamav_profile" in runtime:
        # Formerly under [runtime] — collided with runtime.mode naming.
        warnings.warn(
            "config.toml [runtime].clamav_profile migrated to [scan]; "
            "alias removed in oysterAV 0.3.0",
            DeprecationWarning,
            stacklevel=2,
        )
        _log.warning(
            "Migrated deprecated [runtime].clamav_profile → [scan].clamav_profile "
            "(removed in 0.3.0)",
        )
        if "clamav_profile" not in scan:
            scan["clamav_profile"] = runtime["clamav_profile"]
        del runtime["clamav_profile"]
    return raw


def load_config() -> OysterConfig:
    # Resolve via façade so monkeypatches on oyst_core.config.config_path apply.
    from oyst_core import config as cfg_facade

    path = cfg_facade.config_path()
    if not path.exists():
        cfg = OysterConfig()
        save_config(cfg)
        return cfg
    try:
        with path.open("rb") as f:
            raw = tomllib.load(f)
        return OysterConfig.model_validate(_migrate_raw_config(raw))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, ValidationError) as exc:
        return _recover_corrupt_config(path, exc)


def _recover_corrupt_config(path: Path, exc: Exception) -> OysterConfig:
    """Move an unreadable config aside and fall back to defaults."""
    backup = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
    try:
        os.replace(path, backup)
        _log.error("config.toml is corrupt (%s); moved to %s, using defaults", exc, backup)
    except OSError as move_exc:
        _log.error("config.toml is corrupt (%s); backup failed: %s", exc, move_exc)
    return OysterConfig()


_TOML_SHORT_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _toml_str(value: str) -> str:
    """Escape a string for a TOML basic (double-quoted) string."""
    out: list[str] = []
    for ch in value:
        short = _TOML_SHORT_ESCAPES.get(ch)
        if short is not None:
            out.append(short)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _atomic_write_text(path: Path, text: str) -> None:
    """Write via temp file + fsync + rename so readers never see partial TOML."""
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = 0o600
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _toml_str_list(values: list[str]) -> str:
    return ", ".join(_toml_str(v) for v in values)


def save_config(config: OysterConfig) -> None:
    # Resolve via façade so monkeypatches on oyst_core.config.config_path apply.
    from oyst_core import config as cfg_facade

    path = cfg_facade.config_path()
    lines: list[str] = []
    lines.append("[quarantine]")
    lines.append(f"auto = {'true' if config.quarantine.auto else 'false'}")
    lines.append(f"secure_wipe = {'true' if config.quarantine.secure_wipe else 'false'}")
    if config.quarantine.vault_dir:
        lines.append(f"vault_dir = {_toml_str(config.quarantine.vault_dir)}")
    lines.append("")
    lines.append("[clamonacc]")
    lines.append(f"enabled = {'true' if config.clamonacc.enabled else 'false'}")
    lines.append(f"prevention = {'true' if config.clamonacc.prevention else 'false'}")
    lines.append(f"paths = [{_toml_str_list(config.clamonacc.paths)}]")
    lines.append(f"exclude_paths = [{_toml_str_list(config.clamonacc.exclude_paths)}]")
    lines.append("")
    lines.append("[maldet_monitor]")
    lines.append(f"enabled = {'true' if config.maldet_monitor.enabled else 'false'}")
    lines.append(f"mode = {_toml_str(config.maldet_monitor.mode)}")
    lines.append(f"paths = [{_toml_str_list(config.maldet_monitor.paths)}]")
    lines.append("")
    lines.append("[scan]")
    lines.append(f"profile = {_toml_str(config.scan.profile)}")
    lines.append(f"backend = {_toml_str(config.scan.backend)}")
    lines.append(f"clamav_profile = {_toml_str(config.scan.clamav_profile)}")
    lines.append(f"max_filesize = {_toml_str(config.scan.max_filesize)}")
    lines.append(f"max_recursion = {config.scan.max_recursion}")
    lines.append(f"max_files = {config.scan.max_files}")
    lines.append(f"exclude_dirs = [{_toml_str_list(config.scan.exclude_dirs)}]")
    lines.append(f"apply_limits_to = {_toml_str(config.scan.apply_limits_to)}")
    lines.append("")
    lines.append("[clamav]")
    lines.append(f"ignore_sigs = [{_toml_str_list(config.clamav.ignore_sigs)}]")
    lines.append("")
    lines.append("[fangfrisch]")
    lines.append(f"providers = [{_toml_str_list(config.fangfrisch.providers)}]")
    lines.append("")
    lines.append("[schedule]")
    lines.append(f"enabled = {'true' if config.schedule.enabled else 'false'}")
    lines.append(f"profile = {_toml_str(config.schedule.profile)}")
    lines.append(f"packs = [{_toml_str_list(config.schedule.packs)}]")
    lines.append(f"paths = [{_toml_str_list(config.schedule.paths)}]")
    lines.append(f"frequency = {_toml_str(config.schedule.frequency)}")
    lines.append(f"time = {_toml_str(config.schedule.time)}")
    lines.append(f"weekday = {_toml_str(config.schedule.weekday)}")
    lines.append(f"on_calendar = {_toml_str(config.schedule.on_calendar)}")
    lines.append(f"persistent = {'true' if config.schedule.persistent else 'false'}")
    lines.append(f"quarantine = {_toml_str(config.schedule.quarantine)}")
    lines.append(f"backend = {_toml_str(config.schedule.backend)}")
    lines.append("")
    lines.append("[setup]")
    lines.append(f"completed = {'true' if config.setup.completed else 'false'}")
    if config.setup.completed_at:
        lines.append(f"completed_at = {_toml_str(config.setup.completed_at)}")
    if config.setup.skipped_steps:
        lines.append(f"skipped_steps = [{_toml_str_list(config.setup.skipped_steps)}]")
    if config.setup.completed_install:
        lines.append(f"completed_install = {_toml_str(config.setup.completed_install)}")
    lines.append("")
    lines.append("[rkhunter]")
    lines.append(
        f"skip_keypress = {'true' if config.rkhunter.skip_keypress else 'false'}",
    )
    lines.append(f"disable_tests = [{_toml_str_list(config.rkhunter.disable_tests)}]")
    lines.append("")
    lines.append("[lynis]")
    lines.append(f"quick = {'true' if config.lynis.quick else 'false'}")
    lines.append("")
    lines.append("[runtime]")
    lines.append(f"mode = {_toml_str(config.runtime.mode)}")
    auto_sigs = "true" if config.runtime.auto_update_signatures else "false"
    lines.append(f"auto_update_signatures = {auto_sigs}")
    lines.append("")
    lines.append("[firewall]")
    backend = config.firewall.managed_backend
    if backend:
        lines.append(f"managed_backend = {_toml_str(backend)}")
    lines.append("")
    lines.append("[ui]")
    lines.append(f"run_at_startup = {'true' if config.ui.run_at_startup else 'false'}")
    lines.append(f"start_minimized = {'true' if config.ui.start_minimized else 'false'}")
    lines.append(f"minimize_to_tray = {'true' if config.ui.minimize_to_tray else 'false'}")
    lines.append(f"security_news = {'true' if config.ui.security_news else 'false'}")
    lines.append(
        f"security_news_sources = [{_toml_str_list(config.ui.security_news_sources)}]",
    )
    lines.append(f"security_news_max_age_days = {int(config.ui.security_news_max_age_days)}")
    lines.append(f"theme = {_toml_str(config.ui.theme)}")
    lines.append(f"terminal_show_raw = {'true' if config.ui.terminal_show_raw else 'false'}")
    _atomic_write_text(path, "\n".join(lines) + "\n")
