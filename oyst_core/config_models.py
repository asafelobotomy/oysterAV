"""Pydantic config models and shared literals/constants."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from oyst_core.ui_theme import DEFAULT_UI_THEME, UiThemeId

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

ScheduleFrequency = Literal["hourly", "daily", "weekly", "custom"]
ScheduleQuarantine = Literal["auto", "on", "off"]
# inherit → use scan.backend (same pattern as schedule.quarantine=auto → quarantine.auto)
ScheduleBackend = Literal["inherit", "auto", "clamd", "clamscan"]


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
        default_factory=lambda: [
            "arch",
            "ubuntu",
            "debian",
            "fedora",
            "opensuse",
            "oss-security",
        ],
    )
    security_news_max_age_days: int = 14
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
        # Lazy import via façade so monkeypatches on oyst_core.config.data_dir apply.
        from oyst_core import config as cfg_facade

        base = (cfg_facade.data_dir() / "quarantine").resolve()
        if not self.quarantine.vault_dir:
            return base
        candidate = Path(self.quarantine.vault_dir).expanduser().resolve()
        try:
            candidate.relative_to(cfg_facade.data_dir().resolve())
        except ValueError:
            return base
        return candidate
