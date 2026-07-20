"""DISABLE_TESTS overlay helpers for rkhunter."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from oyst_core.privileged.helper import run_privileged_helper

DEFAULTS_OVERLAY_PATH = Path("/etc/rkhunter.d/oysterav-defaults.conf")
DEFAULTS_OVERLAY_HEADER = (
    "# oysterAV managed defaults — DISABLE_TESTS from config.toml [rkhunter]\n"
)

_TEST_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def validate_disable_tests(tests: Sequence[str]) -> list[str]:
    """Validate rkhunter DISABLE_TESTS names. Raises ValueError on reject."""
    out: list[str] = []
    for raw in tests:
        name = str(raw).strip()
        if not name:
            continue
        if not _TEST_NAME_RE.match(name):
            raise ValueError(f"invalid rkhunter test name: {raw}")
        if name not in out:
            out.append(name)
    return out


def build_disable_tests_overlay_text(tests: Sequence[str]) -> str:
    """Build oysterav-defaults.conf body for DISABLE_TESTS."""
    cleaned = validate_disable_tests(tests)
    lines = [DEFAULTS_OVERLAY_HEADER.strip()]
    if cleaned:
        lines.append(f"DISABLE_TESTS={' '.join(cleaned)}")
    else:
        lines.append("# no tests disabled")
    return "\n".join(lines) + "\n"


def apply_disable_tests_overlay(
    tests: Sequence[str],
    *,
    overlay_path: Path | None = None,
) -> dict[str, object]:
    """Write DISABLE_TESTS into oysterav-defaults.conf (caller must be root)."""
    target = DEFAULTS_OVERLAY_PATH if overlay_path is None else overlay_path
    text = build_disable_tests_overlay_text(tests)
    existing = ""
    if target.is_file():
        existing = target.read_text(encoding="utf-8")
    changed = existing != text
    if changed:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o644)
    return {
        "ok": True,
        "changed": changed,
        "overlay": str(target),
        "disable_tests": validate_disable_tests(tests),
    }


def ensure_disable_tests_overlay(tests: Sequence[str] | None = None) -> dict[str, object]:
    """Apply DISABLE_TESTS via privileged helper (best-effort when auth available)."""
    if tests is None:
        from oyst_core.config import load_config

        tests = load_config().rkhunter.disable_tests
    cleaned = validate_disable_tests(tests)
    desired = build_disable_tests_overlay_text(cleaned)
    try:
        if (
            DEFAULTS_OVERLAY_PATH.is_file()
            and DEFAULTS_OVERLAY_PATH.read_text(encoding="utf-8") == desired
        ):
            return {
                "ok": True,
                "changed": False,
                "disable_tests": cleaned,
                "overlay": str(DEFAULTS_OVERLAY_PATH),
            }
    except OSError:
        pass
    argv = ["set-disable-tests", *cleaned] if cleaned else ["set-disable-tests"]
    res = run_privileged_helper("rkhunter-whitelist", argv, timeout=60)
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "set-disable-tests failed").strip()
        return {"ok": False, "error": err, "disable_tests": cleaned}
    return {
        "ok": True,
        "changed": True,
        "message": (res.stdout or "").strip() or "defaults overlay updated",
        "disable_tests": cleaned,
    }
