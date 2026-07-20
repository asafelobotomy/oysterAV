"""Plan and apply rkhunter finding Resolve (whitelist overlay).

Resolve means accept/whitelist for rkhunter via /etc/rkhunter.d/oysterav-whitelist.conf.
It never deletes files or edits sshd_config.

Re-export façade — implementations live in resolve_plan / overlay / disable_tests.
"""

from __future__ import annotations

from oyst_core.packs.rkhunter_disable_tests import (
    DEFAULTS_OVERLAY_HEADER,
    DEFAULTS_OVERLAY_PATH,
    apply_disable_tests_overlay,
    build_disable_tests_overlay_text,
    ensure_disable_tests_overlay,
    validate_disable_tests,
)
from oyst_core.packs.rkhunter_overlay import (
    apply_overlay_line,
    apply_overlay_lines,
    merge_overlay_text,
    resolve_finding,
    resolve_findings_batch,
)
from oyst_core.packs.rkhunter_resolve_plan import (
    ALLOWED_OPTIONS,
    KNOWN_SAFE_HIDDEN,
    OVERLAY_HEADER,
    OVERLAY_PATH,
    RESOLVABLE_THREATS,
    ResolvePlan,
    is_resolvable_threat,
    package_owner,
    path_allowed_for_resolve,
    plan_resolve,
    validate_whitelist_option,
)

__all__ = [
    "ALLOWED_OPTIONS",
    "DEFAULTS_OVERLAY_HEADER",
    "DEFAULTS_OVERLAY_PATH",
    "KNOWN_SAFE_HIDDEN",
    "OVERLAY_HEADER",
    "OVERLAY_PATH",
    "RESOLVABLE_THREATS",
    "ResolvePlan",
    "apply_disable_tests_overlay",
    "apply_overlay_line",
    "apply_overlay_lines",
    "build_disable_tests_overlay_text",
    "ensure_disable_tests_overlay",
    "is_resolvable_threat",
    "merge_overlay_text",
    "package_owner",
    "path_allowed_for_resolve",
    "plan_resolve",
    "resolve_finding",
    "resolve_findings_batch",
    "validate_disable_tests",
    "validate_whitelist_option",
]
