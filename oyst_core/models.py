"""Data models and exit codes."""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, Field

from oyst_core.finding_status import scan_is_clean


class ExitCode(IntEnum):
    SUCCESS = 0
    THREATS_FOUND = 1
    ERROR = 2
    JOB_BUSY = 3
    PRIVILEGE_DENIED = 4
    PACK_MISSING = 5


class PackTier(StrEnum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    OPTIONAL = "optional"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class JobState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(StrEnum):
    QUICK = "quick"
    FULL = "full"
    INTEGRITY = "integrity"
    SUITE = "suite"
    CUSTOM = "custom"


PROFILE_PACKS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["clamav"],
    ScanProfile.FULL: ["clamav", "maldet"],
    ScanProfile.INTEGRITY: ["rkhunter", "chkrootkit", "unhide"],
    ScanProfile.SUITE: ["clamav", "rkhunter", "chkrootkit"],
    ScanProfile.CUSTOM: [],
}

# Audit-only packs run after path scans for the given profile (not via scan_paths).
PROFILE_AUDIT_PACKS: dict[ScanProfile, list[str]] = {
    ScanProfile.SUITE: ["lynis"],
}

# Packs that must use audit() even when listed in --packs / custom selection.
AUDIT_ONLY_PACKS: frozenset[str] = frozenset({"lynis"})

PROFILE_PATHS: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: ["~/Downloads", "~/Desktop"],
    ScanProfile.FULL: ["~"],
    ScanProfile.INTEGRITY: ["/"],
    ScanProfile.SUITE: ["~"],
    ScanProfile.CUSTOM: [],
}


class PackStatus(BaseModel):
    name: str
    tier: PackTier
    installed: bool
    version: str | None = None
    min_version: str | None = None
    version_ok: bool = True
    message: str = ""
    install_hint: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    pack: str
    path: str
    threat_name: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    message: str = ""
    raw_line: str = ""
    quarantined: bool = False
    resolved: bool = False


class PackError(BaseModel):
    pack: str
    error: str


class ScanResult(BaseModel):
    job_id: str
    profile: ScanProfile
    paths: list[str]
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    pack_errors: list[PackError] = Field(default_factory=list)
    clean: bool = True
    state: JobState = JobState.COMPLETED

    def finalize(self) -> None:
        self.finished_at = datetime.now()
        self.clean = scan_is_clean(self.findings)
        if self.state not in (JobState.CANCELLED, JobState.FAILED):
            self.state = JobState.COMPLETED


class QuarantineEntry(BaseModel):
    id: int
    original_path: str
    vault_path: str
    sha256: str
    threat_name: str = ""
    quarantined_at: datetime
