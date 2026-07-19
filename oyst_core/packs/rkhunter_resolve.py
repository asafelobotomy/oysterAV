"""Plan and apply rkhunter finding Resolve (whitelist overlay).

Resolve means accept/whitelist for rkhunter via /etc/rkhunter.d/oysterav-whitelist.conf.
It never deletes files or edits sshd_config.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from oyst_core.privileged.helper import run_privileged_helper

OVERLAY_PATH = Path("/etc/rkhunter.d/oysterav-whitelist.conf")
DEFAULTS_OVERLAY_PATH = Path("/etc/rkhunter.d/oysterav-defaults.conf")
OVERLAY_HEADER = "# oysterAV managed — do not edit by hand unless you know why\n"
DEFAULTS_OVERLAY_HEADER = (
    "# oysterAV managed defaults — DISABLE_TESTS from config.toml [rkhunter]\n"
)

RESOLVABLE_THREATS = frozenset(
    {
        "rkhunter-script-replacement",
        "rkhunter-hidden",
        "rkhunter-ssh",
    }
)

_MULTI_VALUE_OPTIONS = frozenset({"SCRIPTWHITELIST", "ALLOWHIDDENFILE"})
_SINGLE_VALUE_OPTIONS = frozenset({"ALLOW_SSH_PROT_V1", "ALLOW_SSH_ROOT_USER"})
ALLOWED_OPTIONS = _MULTI_VALUE_OPTIONS | _SINGLE_VALUE_OPTIONS

_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
_SSH_PROT_VALUES = frozenset({"2"})
_SSH_ROOT_VALUES = frozenset({"unset"})
_TEST_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# systemd-update-done stamp files are not package-owned but are expected.
KNOWN_SAFE_HIDDEN = frozenset(
    {
        "/etc/.updated",
        "/var/.updated",
    }
)


@dataclass(frozen=True)
class ResolvePlan:
    threat_name: str
    option: str
    value: str
    explanation: str
    requires_path: bool


def is_resolvable_threat(threat_name: str) -> bool:
    return threat_name in RESOLVABLE_THREATS


def validate_whitelist_option(option: str, value: str) -> tuple[str, str]:
    """Validate option/value for helper writes. Raises ValueError on reject."""
    opt = option.strip()
    val = value.strip()
    if opt not in ALLOWED_OPTIONS:
        raise ValueError(f"option not allowlisted: {option}")
    if opt in _MULTI_VALUE_OPTIONS:
        if not _PATH_RE.match(val):
            raise ValueError(f"invalid whitelist path: {value}")
        return opt, val
    if opt == "ALLOW_SSH_PROT_V1":
        if val not in _SSH_PROT_VALUES:
            raise ValueError(f"invalid ALLOW_SSH_PROT_V1 value: {value}")
        return opt, val
    if opt == "ALLOW_SSH_ROOT_USER":
        if val not in _SSH_ROOT_VALUES:
            raise ValueError(f"invalid ALLOW_SSH_ROOT_USER value: {value}")
        return opt, val
    raise ValueError(f"option not allowlisted: {option}")


def plan_resolve(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
) -> ResolvePlan:
    """Map a finding to a single overlay directive."""
    threat = threat_name.strip()
    if threat not in RESOLVABLE_THREATS:
        raise ValueError(f"threat not resolvable: {threat_name}")

    if threat == "rkhunter-script-replacement":
        cleaned = _require_abs_path(path)
        return ResolvePlan(
            threat_name=threat,
            option="SCRIPTWHITELIST",
            value=cleaned,
            explanation=(
                f"Whitelist package-owned script {cleaned} in rkhunter "
                f"(SCRIPTWHITELIST). This does not change the file; it only "
                f"stops rkhunter treating a known distro wrapper as a warning."
            ),
            requires_path=True,
        )

    if threat == "rkhunter-hidden":
        cleaned = _require_abs_path(path)
        return ResolvePlan(
            threat_name=threat,
            option="ALLOWHIDDENFILE",
            value=cleaned,
            explanation=(
                f"Allow hidden file {cleaned} in rkhunter (ALLOWHIDDENFILE). "
                f"This does not delete or modify the file."
            ),
            requires_path=True,
        )

    # rkhunter-ssh
    lower = message.lower()
    if "protocol" in lower:
        return ResolvePlan(
            threat_name=threat,
            option="ALLOW_SSH_PROT_V1",
            value="2",
            explanation=(
                "Tell rkhunter that an unset SSH Protocol option is acceptable "
                "(ALLOW_SSH_PROT_V1=2). Modern OpenSSH only supports protocol 2; "
                "this does not edit sshd_config."
            ),
            requires_path=False,
        )
    if "permitrootlogin" in lower:
        return ResolvePlan(
            threat_name=threat,
            option="ALLOW_SSH_ROOT_USER",
            value="unset",
            explanation=(
                "Tell rkhunter that an unset PermitRootLogin option is acceptable "
                "(ALLOW_SSH_ROOT_USER=unset). OpenSSH still applies its default; "
                "this does not edit sshd_config. Harden SSH separately if desired."
            ),
            requires_path=False,
        )
    raise ValueError(f"unrecognized SSH finding message: {message[:120]}")


def package_owner(path: str) -> str | None:
    """Return owning package name if a supported package manager reports one."""
    target = Path(path)
    checkers: list[list[str]] = []
    if shutil.which("pacman"):
        checkers.append(["pacman", "-Qo", "--", str(target)])
    if shutil.which("rpm"):
        checkers.append(["rpm", "-qf", str(target)])
    if shutil.which("dpkg"):
        checkers.append(["dpkg", "-S", str(target)])
    for argv in checkers:
        try:
            proc = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode != 0:
            continue
        text = (proc.stdout or proc.stderr or "").strip()
        if text:
            return text.splitlines()[0][:200]
    return None


def path_allowed_for_resolve(path: str, threat_name: str, *, force: bool = False) -> None:
    """Raise ValueError if path must not be whitelisted without --force."""
    cleaned = _require_abs_path(path)
    p = Path(cleaned)
    if not p.exists():
        raise ValueError(f"path does not exist: {cleaned}")
    if force:
        return
    if threat_name == "rkhunter-hidden" and cleaned in KNOWN_SAFE_HIDDEN:
        return
    owner = package_owner(cleaned)
    if owner is None:
        raise ValueError(f"path is not package-owned (refusing without --force): {cleaned}")


def merge_overlay_text(existing: str, option: str, value: str) -> tuple[str, bool]:
    """Merge one directive into overlay text. Returns (new_text, changed)."""
    opt, val = validate_whitelist_option(option, value)
    line = f"{opt}={val}"
    lines = [ln.rstrip("\n") for ln in existing.splitlines() if ln.strip() != ""]
    if not lines or not lines[0].startswith("# oysterAV managed"):
        lines = [OVERLAY_HEADER.strip(), *lines]

    if opt in _SINGLE_VALUE_OPTIONS:
        out: list[str] = []
        replaced = False
        changed = False
        for ln in lines:
            if ln.startswith("#"):
                out.append(ln)
                continue
            if ln.startswith(f"{opt}="):
                if ln == line:
                    out.append(ln)
                    replaced = True
                else:
                    out.append(line)
                    replaced = True
                    changed = True
            else:
                out.append(ln)
        if not replaced:
            out.append(line)
            changed = True
        text = "\n".join(out) + "\n"
        return text, changed

    # multi-value: append if missing
    if line in lines:
        return "\n".join(lines) + "\n", False
    lines.append(line)
    return "\n".join(lines) + "\n", True


def apply_overlay_line(
    option: str,
    value: str,
    *,
    overlay_path: Path | None = None,
) -> dict[str, object]:
    """Write one directive into the oysterAV rkhunter overlay (caller must be root)."""
    result = apply_overlay_lines([(option, value)], overlay_path=overlay_path)
    applied = result.get("applied")
    first = applied[0] if isinstance(applied, list) and applied else {}
    return {
        "ok": True,
        "changed": bool(result.get("changed")),
        "option": first.get("option", option) if isinstance(first, dict) else option,
        "value": first.get("value", value) if isinstance(first, dict) else value,
        "overlay": result.get("overlay", str(OVERLAY_PATH)),
    }


def apply_overlay_lines(
    directives: Sequence[tuple[str, str]],
    *,
    overlay_path: Path | None = None,
) -> dict[str, object]:
    """Write many directives into the overlay in one file update (caller must be root)."""
    target = OVERLAY_PATH if overlay_path is None else overlay_path
    if not directives:
        return {
            "ok": True,
            "changed": False,
            "applied": [],
            "overlay": str(target),
        }
    existing = ""
    if target.is_file():
        existing = target.read_text(encoding="utf-8")
    changed_any = False
    applied: list[dict[str, object]] = []
    text = existing
    for option, value in directives:
        opt, val = validate_whitelist_option(option, value)
        text, changed = merge_overlay_text(text, opt, val)
        if changed:
            changed_any = True
        applied.append({"option": opt, "value": val, "changed": changed})
    if changed_any:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o644)
    return {
        "ok": True,
        "changed": changed_any,
        "applied": applied,
        "overlay": str(target),
    }


def resolve_finding(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    """Plan and optionally apply a Resolve for one finding."""
    batch = resolve_findings_batch(
        [{"threat_name": threat_name, "path": path, "message": message}],
        force=force,
        dry_run=dry_run,
    )
    items = batch.get("items")
    first = items[0] if isinstance(items, list) and items else None
    if isinstance(first, dict):
        return first
    errors = batch.get("errors") or []
    err = errors[0] if isinstance(errors, list) and errors else "resolve failed"
    return {"ok": False, "error": str(err), "threat_name": threat_name}


def resolve_findings_batch(
    findings: Sequence[dict[str, object]],
    *,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    """Plan many findings, then apply all allowlisted directives in one privileged write.

    Path/ownership gates still run per finding before the helper is invoked.
    """
    planned: list[tuple[dict[str, object], ResolvePlan]] = []
    errors: list[str] = []

    for raw in findings:
        threat = str(raw.get("threat_name") or "")
        path = str(raw.get("path") or "")
        message = str(raw.get("message") or "")
        try:
            plan = plan_resolve(threat, path=path, message=message)
            if plan.requires_path:
                path_allowed_for_resolve(plan.value, plan.threat_name, force=force)
        except ValueError as exc:
            errors.append(f"{threat or path or 'finding'}: {exc}")
            continue
        planned.append((raw, plan))

    items: list[dict[str, object]] = []
    for raw, plan in planned:
        items.append(
            {
                "ok": True,
                "threat_name": plan.threat_name,
                "path": str(raw.get("path") or ""),
                "message": str(raw.get("message") or ""),
                "option": plan.option,
                "value": plan.value,
                "explanation": plan.explanation,
                "overlay": str(OVERLAY_PATH),
            }
        )

    if dry_run:
        for item in items:
            item["dry_run"] = True
            item["changed"] = None
        return {
            "ok": len(errors) == 0,
            "resolved": len(items),
            "errors": errors,
            "items": items,
            "dry_run": True,
        }

    if not planned:
        return {
            "ok": len(errors) == 0,
            "resolved": 0,
            "errors": errors,
            "items": [],
        }

    directives: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for _, plan in planned:
        key = (plan.option, plan.value)
        if key in seen:
            continue
        seen.add(key)
        directives.append(key)

    argv = ["set-many", *[f"{opt}={val}" for opt, val in directives]]
    res = run_privileged_helper("rkhunter-whitelist", argv, timeout=60)
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "rkhunter-whitelist set-many failed").strip()
        for item in items:
            item["ok"] = False
            item["error"] = err
        errors.extend(f"{item.get('threat_name')}: {err}" for item in items)
        return {
            "ok": False,
            "resolved": 0,
            "errors": errors,
            "items": items,
        }

    message = (res.stdout or "").strip() or "whitelist updated"
    for item in items:
        item["changed"] = True
        item["message"] = message
    return {
        "ok": len(errors) == 0,
        "resolved": len(items),
        "errors": errors,
        "items": items,
    }


def _require_abs_path(path: str) -> str:
    cleaned = path.strip()
    if not cleaned or cleaned == "system":
        raise ValueError("absolute path required")
    if not _PATH_RE.match(cleaned):
        raise ValueError(f"invalid path: {path}")
    return cleaned


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
