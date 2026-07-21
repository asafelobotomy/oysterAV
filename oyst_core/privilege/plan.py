"""Privilege concert plan types (userspace)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PrivilegeStep:
    """One labeled step in a user-facing privilege plan."""

    id: str
    label: str
    privileged: bool = True
    priority: int = 50


@dataclass
class PrivilegePlan:
    """Declarative plan for a single user action that may need one polkit auth."""

    recipe: str
    title: str
    summary: str
    argv1: str
    helper_argv: list[str] = field(default_factory=list)
    privileged_steps: list[PrivilegeStep] = field(default_factory=list)
    local_steps: list[PrivilegeStep] = field(default_factory=list)
    disclosure_only: bool = False

    @property
    def needs_elevation(self) -> bool:
        if self.disclosure_only:
            return bool(self.privileged_steps)
        return bool(self.privileged_steps) and bool(self.helper_argv)

    def ordered_privileged_steps(self) -> list[PrivilegeStep]:
        """Privileged steps sorted by priority then id."""
        return sorted(self.privileged_steps, key=lambda s: (s.priority, s.id))

    def ordered_local_steps(self) -> list[PrivilegeStep]:
        return sorted(self.local_steps, key=lambda s: (s.priority, s.id))

    def to_helper_argv(self) -> list[str]:
        """Argv passed to oyst-helper after argv1."""
        return list(self.helper_argv)


# Packs that require root helper during a scan job.
PRIVILEGED_SCAN_PACKS = frozenset({"rkhunter", "chkrootkit", "unhide", "lynis"})
LOCAL_SCAN_PACKS = frozenset({"clamav", "maldet"})
