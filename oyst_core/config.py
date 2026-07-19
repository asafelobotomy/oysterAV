"""XDG configuration management."""

from __future__ import annotations

import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, Field, field_validator

from oyst_core.ui_theme import DEFAULT_UI_THEME, UI_THEME_ID_SET, UiThemeId

RuntimeMode = Literal["full", "lite"]
ClamavProfile = Literal["full", "linux-only"]
ApplyLimitsTo = Literal["quick", "all"]

KNOWN_FANGFRISCH_PROVIDERS: frozenset[str] = frozenset(
    {
        "sanesecurity",
        "urlhaus",
        "interserver",
        "malwarepatrol",
        "securiteInfo",
    },
)

_RKHUNTER_TEST_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SIG_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_FILESIZE_RE = re.compile(r"^\d+[KMGkmg]?$")


def config_dir() -> Path:
    path = Path.home() / ".config" / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_dir() -> Path:
    path = Path.home() / ".local" / "share" / "oysterav"
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    return config_dir() / "config.toml"


class QuarantineConfig(BaseModel):
    auto: bool = False
    vault_dir: str = ""


class ClamonaccConfig(BaseModel):
    enabled: bool = False
    paths: list[str] = Field(default_factory=lambda: ["~/Downloads", "~/Desktop"])
    prevention: bool = False
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["~/.cache", "~/.local/share/Trash"],
    )


class MaldetMonitorConfig(BaseModel):
    enabled: bool = False
    mode: str = "users"
    paths: list[str] = Field(default_factory=list)


class ScanDefaults(BaseModel):
    """Interactive scan defaults (manual CLI/GUI). Schedule has its own overrides."""

    profile: str = "quick"
    backend: str = "auto"
    # PE scan mode for clamscan only — not runtime.mode (full/lite install delivery).
    clamav_profile: ClamavProfile = "full"
    max_filesize: str = "25M"
    max_recursion: int = 8
    max_files: int = 10000
    # clamscan --exclude-dir (not clamonacc.exclude_paths / on-access).
    exclude_dirs: list[str] = Field(default_factory=list)
    apply_limits_to: ApplyLimitsTo = "quick"

    @field_validator("max_filesize")
    @classmethod
    def _validate_max_filesize(cls, value: str) -> str:
        cleaned = value.strip()
        if not _MAX_FILESIZE_RE.match(cleaned):
            raise ValueError("max_filesize must look like 25M or 100K")
        return cleaned

    @field_validator("max_recursion", "max_files")
    @classmethod
    def _validate_positive_int(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be >= 1")
        return value


class ClamavConfig(BaseModel):
    ignore_sigs: list[str] = Field(default_factory=list)

    @field_validator("ignore_sigs")
    @classmethod
    def _validate_ignore_sigs(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for raw in value:
            name = raw.strip()
            if not name:
                continue
            if not _SIG_NAME_RE.match(name):
                raise ValueError(f"invalid signature name: {raw}")
            out.append(name)
        return out


class FangfrischConfig(BaseModel):
    providers: list[str] = Field(
        default_factory=lambda: ["sanesecurity", "urlhaus"],
    )

    @field_validator("providers")
    @classmethod
    def _validate_providers(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for raw in value:
            name = raw.strip()
            if not name:
                continue
            if name not in KNOWN_FANGFRISCH_PROVIDERS:
                raise ValueError(
                    "fangfrisch provider must be one of: "
                    + ", ".join(sorted(KNOWN_FANGFRISCH_PROVIDERS)),
                )
            if name not in out:
                out.append(name)
        return out


ScheduleFrequency = Literal["hourly", "daily", "weekly", "custom"]
ScheduleQuarantine = Literal["auto", "on", "off"]
# inherit → use scan.backend (same pattern as schedule.quarantine=auto → quarantine.auto)
ScheduleBackend = Literal["inherit", "auto", "clamd", "clamscan"]


class ScheduleConfig(BaseModel):
    enabled: bool = False
    profile: str = "quick"
    packs: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    frequency: ScheduleFrequency = "daily"
    time: str = "02:00"
    weekday: str = "mon"
    on_calendar: str = ""
    persistent: bool = True
    quarantine: ScheduleQuarantine = "auto"
    backend: ScheduleBackend = "inherit"


class SetupConfig(BaseModel):
    completed: bool = False
    completed_at: str | None = None
    skipped_steps: list[str] = Field(default_factory=list)


class RKHunterConfig(BaseModel):
    skip_keypress: bool = True
    disable_tests: list[str] = Field(default_factory=lambda: ["suspscan"])

    @field_validator("disable_tests")
    @classmethod
    def _validate_disable_tests(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for raw in value:
            name = raw.strip()
            if not name:
                continue
            if not _RKHUNTER_TEST_RE.match(name):
                raise ValueError(f"invalid rkhunter test name: {raw}")
            if name not in out:
                out.append(name)
        return out


class LynisConfig(BaseModel):
    quick: bool = True


class RuntimeConfig(BaseModel):
    """Install/delivery mode only — PE scan mode lives under scan.clamav_profile."""

    mode: RuntimeMode = "full"


class UiConfig(BaseModel):
    run_at_startup: bool = False
    start_minimized: bool = False
    minimize_to_tray: bool = False
    security_news: bool = True
    security_news_sources: list[str] = Field(
        default_factory=lambda: ["arch", "ubuntu", "debian"],
    )
    theme: UiThemeId = DEFAULT_UI_THEME


class OysterConfig(BaseModel):
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)
    clamonacc: ClamonaccConfig = Field(default_factory=ClamonaccConfig)
    maldet_monitor: MaldetMonitorConfig = Field(default_factory=MaldetMonitorConfig)
    scan: ScanDefaults = Field(default_factory=ScanDefaults)
    clamav: ClamavConfig = Field(default_factory=ClamavConfig)
    fangfrisch: FangfrischConfig = Field(default_factory=FangfrischConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    setup: SetupConfig = Field(default_factory=SetupConfig)
    rkhunter: RKHunterConfig = Field(default_factory=RKHunterConfig)
    lynis: LynisConfig = Field(default_factory=LynisConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    ui: UiConfig = Field(default_factory=UiConfig)

    def vault_path(self) -> Path:
        if self.quarantine.vault_dir:
            return Path(self.quarantine.vault_dir).expanduser()
        return data_dir() / "quarantine"


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
        if "clamav_profile" not in scan:
            scan["clamav_profile"] = runtime["clamav_profile"]
        del runtime["clamav_profile"]
    return raw


def load_config() -> OysterConfig:
    path = config_path()
    if not path.exists():
        cfg = OysterConfig()
        save_config(cfg)
        return cfg
    with path.open("rb") as f:
        raw = tomllib.load(f)
    return OysterConfig.model_validate(_migrate_raw_config(raw))


def effective_scan_backend(cfg: OysterConfig | None = None) -> str:
    """Backend for interactive / manual scans."""
    return (cfg or load_config()).scan.backend


def effective_schedule_backend(
    cfg: OysterConfig | None = None,
    *,
    schedule: ScheduleConfig | None = None,
) -> str:
    """Backend for the systemd timer — inherit uses scan.backend."""
    c = cfg or load_config()
    sched = schedule if schedule is not None else c.schedule
    if sched.backend == "inherit":
        return c.scan.backend
    return sched.backend


def _toml_str(value: str) -> str:
    """Escape a string for double-quoted TOML."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _toml_str_list(values: list[str]) -> str:
    return ", ".join(_toml_str(v) for v in values)


def save_config(config: OysterConfig) -> None:
    path = config_path()
    lines: list[str] = []
    lines.append("[quarantine]")
    lines.append(f"auto = {'true' if config.quarantine.auto else 'false'}")
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
    lines.append("")
    lines.append("[ui]")
    lines.append(f"run_at_startup = {'true' if config.ui.run_at_startup else 'false'}")
    lines.append(f"start_minimized = {'true' if config.ui.start_minimized else 'false'}")
    lines.append(f"minimize_to_tray = {'true' if config.ui.minimize_to_tray else 'false'}")
    lines.append(f"security_news = {'true' if config.ui.security_news else 'false'}")
    lines.append(
        f"security_news_sources = [{_toml_str_list(config.ui.security_news_sources)}]",
    )
    lines.append(f"theme = {_toml_str(config.ui.theme)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_config_value(key: str) -> str | None:
    if key == "runtime.clamav_profile":
        # Deprecated alias for scan.clamav_profile
        key = "scan.clamav_profile"
    cfg = load_config()
    flat = cfg.model_dump()
    parts = key.split(".")
    cur: Any = flat
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if isinstance(cur, bool):
        return "true" if cur else "false"
    if isinstance(cur, list):
        return ",".join(str(v) for v in cur)
    return str(cur)


def _parse_bool(value: str) -> bool:
    return value.lower() in ("true", "1", "yes")


def _parse_csv(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


def set_config_value(key: str, value: str) -> None:
    cfg = load_config()
    old: str | None = None
    try:
        old = get_config_value(key)
    except KeyError:
        old = None
    if key == "quarantine.auto":
        cfg.quarantine.auto = _parse_bool(value)
    elif key == "scan.profile":
        cfg.scan.profile = value
    elif key == "scan.backend":
        cfg.scan.backend = value
    elif key == "scan.clamav_profile":
        if value not in ("full", "linux-only"):
            raise KeyError("scan.clamav_profile must be 'full' or 'linux-only'")
        cfg.scan.clamav_profile = cast(ClamavProfile, value)
    elif key == "runtime.clamav_profile":
        # Deprecated alias — PE mode lives under scan (not runtime.mode).
        if value not in ("full", "linux-only"):
            raise KeyError("scan.clamav_profile must be 'full' or 'linux-only'")
        cfg.scan.clamav_profile = cast(ClamavProfile, value)
    elif key == "scan.max_filesize":
        if not _MAX_FILESIZE_RE.match(value.strip()):
            raise KeyError("scan.max_filesize must look like 25M or 100K")
        cfg.scan.max_filesize = value.strip()
    elif key == "scan.max_recursion":
        try:
            parsed = int(value)
        except ValueError as exc:
            raise KeyError("scan.max_recursion must be an integer") from exc
        if parsed < 1:
            raise KeyError("scan.max_recursion must be >= 1")
        cfg.scan.max_recursion = parsed
    elif key == "scan.max_files":
        try:
            parsed = int(value)
        except ValueError as exc:
            raise KeyError("scan.max_files must be an integer") from exc
        if parsed < 1:
            raise KeyError("scan.max_files must be >= 1")
        cfg.scan.max_files = parsed
    elif key == "scan.exclude_dirs":
        cfg.scan.exclude_dirs = _parse_csv(value)
    elif key == "scan.apply_limits_to":
        if value not in ("quick", "all"):
            raise KeyError("scan.apply_limits_to must be 'quick' or 'all'")
        cfg.scan.apply_limits_to = cast(ApplyLimitsTo, value)
    elif key == "clamav.ignore_sigs":
        names = _parse_csv(value)
        for name in names:
            if not _SIG_NAME_RE.match(name):
                raise KeyError(f"invalid signature name: {name}")
        cfg.clamav.ignore_sigs = names
    elif key == "fangfrisch.providers":
        providers = _parse_csv(value)
        for name in providers:
            if name not in KNOWN_FANGFRISCH_PROVIDERS:
                raise KeyError(
                    "fangfrisch.providers must be a subset of: "
                    + ", ".join(sorted(KNOWN_FANGFRISCH_PROVIDERS)),
                )
        cfg.fangfrisch.providers = providers
    elif key == "clamonacc.enabled":
        cfg.clamonacc.enabled = _parse_bool(value)
    elif key == "clamonacc.prevention":
        cfg.clamonacc.prevention = _parse_bool(value)
    elif key == "clamonacc.paths":
        cfg.clamonacc.paths = _parse_csv(value)
    elif key == "clamonacc.exclude_paths":
        cfg.clamonacc.exclude_paths = _parse_csv(value)
    elif key == "maldet_monitor.enabled":
        cfg.maldet_monitor.enabled = _parse_bool(value)
    elif key == "maldet_monitor.mode":
        if value not in ("users", "paths"):
            raise KeyError("maldet_monitor.mode must be 'users' or 'paths'")
        cfg.maldet_monitor.mode = value
    elif key == "maldet_monitor.paths":
        cfg.maldet_monitor.paths = _parse_csv(value)
    elif key == "setup.completed":
        cfg.setup.completed = _parse_bool(value)
        if cfg.setup.completed and not cfg.setup.completed_at:
            cfg.setup.completed_at = datetime.now(UTC).isoformat()
        if not cfg.setup.completed:
            cfg.setup.completed_at = None
    elif key == "setup.skipped_steps":
        cfg.setup.skipped_steps = _parse_csv(value)
    elif key == "rkhunter.skip_keypress":
        cfg.rkhunter.skip_keypress = _parse_bool(value)
    elif key == "rkhunter.disable_tests":
        tests = _parse_csv(value)
        for name in tests:
            if not _RKHUNTER_TEST_RE.match(name):
                raise KeyError(f"invalid rkhunter test name: {name}")
        cfg.rkhunter.disable_tests = tests
    elif key == "lynis.quick":
        cfg.lynis.quick = _parse_bool(value)
    elif key == "runtime.mode":
        if value not in ("full", "lite"):
            raise KeyError("runtime.mode must be 'full' or 'lite'")
        cfg.runtime.mode = cast(RuntimeMode, value)
    elif key == "schedule.enabled":
        cfg.schedule.enabled = _parse_bool(value)
    elif key == "schedule.profile":
        cfg.schedule.profile = value
    elif key == "schedule.packs":
        cfg.schedule.packs = _parse_csv(value)
    elif key == "schedule.paths":
        cfg.schedule.paths = _parse_csv(value)
    elif key == "schedule.frequency":
        if value not in ("hourly", "daily", "weekly", "custom"):
            raise KeyError("schedule.frequency must be hourly|daily|weekly|custom")
        cfg.schedule.frequency = cast(ScheduleFrequency, value)
    elif key == "schedule.time":
        cfg.schedule.time = value
    elif key == "schedule.weekday":
        cfg.schedule.weekday = value
    elif key == "schedule.on_calendar":
        from oyst_core.schedule_util import sanitize_on_calendar

        cfg.schedule.on_calendar = sanitize_on_calendar(value)
    elif key == "schedule.persistent":
        cfg.schedule.persistent = _parse_bool(value)
    elif key == "schedule.quarantine":
        if value not in ("auto", "on", "off"):
            raise KeyError("schedule.quarantine must be auto|on|off")
        cfg.schedule.quarantine = cast(ScheduleQuarantine, value)
    elif key == "schedule.backend":
        if value not in ("inherit", "auto", "clamd", "clamscan"):
            raise KeyError("schedule.backend must be inherit|auto|clamd|clamscan")
        cfg.schedule.backend = cast(ScheduleBackend, value)
    elif key == "ui.run_at_startup":
        cfg.ui.run_at_startup = _parse_bool(value)
    elif key == "ui.start_minimized":
        cfg.ui.start_minimized = _parse_bool(value)
    elif key == "ui.minimize_to_tray":
        cfg.ui.minimize_to_tray = _parse_bool(value)
    elif key == "ui.security_news":
        cfg.ui.security_news = _parse_bool(value)
    elif key == "ui.security_news_sources":
        from oyst_core.security_news import normalize_source_ids

        cfg.ui.security_news_sources = normalize_source_ids(_parse_csv(value))
    elif key == "ui.theme":
        if value not in UI_THEME_ID_SET:
            raise KeyError(
                "ui.theme must be one of: " + ", ".join(sorted(UI_THEME_ID_SET)),
            )
        cfg.ui.theme = cast(UiThemeId, value)
    else:
        raise KeyError(f"Unknown config key: {key}")
    save_config(cfg)

    # Side-effects for desktop integration (after persist).
    if key == "ui.run_at_startup":
        from oyst_core.desktop_util import sync_autostart_from_config

        sync_autostart_from_config()
    elif key == "ui.start_minimized":
        from oyst_core.desktop_util import rewrite_autostart_if_enabled

        rewrite_autostart_if_enabled()
    elif key == "clamav.ignore_sigs":
        from oyst_core.packs.clamav import ClamAVPack

        ClamAVPack().ensure_ignore_sigs()
    elif key == "rkhunter.disable_tests":
        from oyst_core.packs.rkhunter_resolve import ensure_disable_tests_overlay

        ensure_disable_tests_overlay(cfg.rkhunter.disable_tests)
    elif key == "fangfrisch.providers":
        from oyst_core.packs.fangfrisch import FangfrischPack

        FangfrischPack().ensure_config(force=True)

    from oyst_core.audit import SecurityAudit

    SecurityAudit().log("config.set", key, success=True, data={"old": old, "new": value})


def setup_status() -> dict[str, object]:
    from oyst_core.setup_workflow import assess_setup

    return assess_setup()
