"""Install oyst-helper and polkit policy for privileged operations."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

from oyst_core.privileged.auth_grant import migrate_grant_on_helper_install
from oyst_core.privileged.auth_grant_scope import (
    SERVICE_LIFECYCLE_ACTION_IDS as SERVICE_LIFECYCLE_ACTION_IDS,
)
from oyst_core.privileged.polkit_policy import build_polkit_policy
from oyst_core.privileged.runner import run_command

HELPER_DIR = Path("/usr/lib/oysterav")
HELPER_PATH = HELPER_DIR / "oyst-helper"
# Legacy path from source installs before packaging alignment.
HELPER_PATH_LEGACY = Path("/usr/local/lib/oysterav/oyst-helper")
POLKIT_PATH = Path("/usr/share/polkit-1/actions/io.github.asafelobotomy.policy")

# Bump when action IDs / argv1 annotations / exec.path change (helper-status reports this).
POLICY_VERSION = 12

POLKIT_ACTION_IDS = (
    "io.github.asafelobotomy.helper.systemctl",
    "io.github.asafelobotomy.helper.systemctl-up",
    "io.github.asafelobotomy.helper.run",
    "io.github.asafelobotomy.helper.firewall",
    "io.github.asafelobotomy.helper.fail2ban",
    "io.github.asafelobotomy.helper.maldet-config",
    "io.github.asafelobotomy.helper.rkhunter-whitelist",
    "io.github.asafelobotomy.helper.clamd-cocontrol",
    "io.github.asafelobotomy.helper.setup-harden",
    "io.github.asafelobotomy.helper.setup-concert",
    "io.github.asafelobotomy.helper.scan-concert",
    "io.github.asafelobotomy.helper.update-concert",
    "io.github.asafelobotomy.helper.install-script",
    "io.github.asafelobotomy.helper.run-sealed",
)

HELPER_SCRIPT = textwrap.dedent(
    """\
    #!{python}
    from oyst_core.privileged.oyst_helper import main
    main()
    """,
)

HELPER_SCRIPT_WITH_SITE = textwrap.dedent(
    """\
    #!{python}
    import sys
    sys.path.insert(0, {site_root!r})
    from oyst_core.privileged.oyst_helper import main
    main()
    """,
)

_TRUSTED_BIN_PREFIXES = ("/usr/bin/", "/usr/local/bin/")


def _is_root_owned_system_bin(path: Path) -> bool:
    try:
        resolved = path.resolve()
        st = resolved.stat()
    except OSError:
        return False
    if st.st_uid != 0:
        return False
    text = str(resolved)
    return text.startswith(_TRUSTED_BIN_PREFIXES)


def _resolve_trusted_helper_python(*, allow_untrusted: bool) -> str:
    """Prefer a root-owned system interpreter; refuse user/venv shebangs for real installs."""
    for candidate in ("/usr/bin/python3", "/usr/bin/python"):
        path = Path(candidate)
        if path.is_file() and _is_root_owned_system_bin(path):
            return str(path.resolve())
    exe = Path(sys.executable).resolve()
    if _is_root_owned_system_bin(exe):
        return str(exe)
    if allow_untrusted:
        return str(exe)
    raise OSError(
        "Refusing to install oyst-helper with a user-writable interpreter "
        f"({sys.executable}). Install oysterAV via a distro package so "
        "/usr/bin/python3 can import oyst_core.",
    )


def _oyst_core_site_root() -> Path:
    """Directory that must be on sys.path for ``import oyst_core``."""
    import oyst_core

    return Path(oyst_core.__file__).resolve().parent.parent


def _python_imports_oyst_core(python: str, *, site_root: Path | None = None) -> bool:
    """Return True if *python* can import oyst_core (with optional site_root)."""
    code = "import oyst_core"
    if site_root is not None:
        code = f"import sys; sys.path.insert(0, {str(site_root)!r}); import oyst_core"
    try:
        proc = subprocess.run(
            [python, "-c", code],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            # Avoid false positives when the installer cwd is a source checkout.
            cwd="/",
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _validate_site_root(path: Path, *, require_root_owned: bool = True) -> Path:
    resolved = path.resolve()
    if not resolved.is_absolute():
        raise OSError(f"oyst_core site root must be absolute: {path}")
    if ".." in path.parts:
        raise OSError(f"oyst_core site root must not contain ..: {path}")
    pkg = resolved / "oyst_core"
    if not pkg.is_dir() or not (pkg / "__init__.py").is_file():
        raise OSError(f"oyst_core package not found under {resolved}")
    if not require_root_owned:
        return resolved
    try:
        st = resolved.stat()
    except OSError as exc:
        raise OSError(f"cannot stat oyst_core site root {resolved}: {exc}") from exc
    if st.st_uid != 0:
        raise OSError(
            f"Refusing to embed user-writable site root {resolved} in oyst-helper "
            "(must be root-owned). Install oysterAV via a distro package, or place "
            "oyst_core under a root-owned prefix.",
        )
    if st.st_mode & 0o022:
        raise OSError(
            f"Refusing to embed world/group-writable site root {resolved} in oyst-helper",
        )
    return resolved


def _helper_script_text(*, allow_untrusted_python: bool = False) -> str:
    """Bind the helper to a trusted system interpreter when possible.

    Distro installs expect ``oyst_core`` on the system interpreter's path. Source /
    uv checkouts do not — embed an absolute site root so pkexec (cwd=/) still works.
    """
    python = _resolve_trusted_helper_python(allow_untrusted=allow_untrusted_python)
    if _python_imports_oyst_core(python):
        return HELPER_SCRIPT.format(python=python)
    site_root = _validate_site_root(
        _oyst_core_site_root(),
        require_root_owned=not allow_untrusted_python,
    )
    if not _python_imports_oyst_core(python, site_root=site_root):
        raise OSError(
            f"{python} cannot import oyst_core even with site root {site_root}. "
            "Reinstall oysterAV or run: oyst-cli install-privileged-helper",
        )
    return HELPER_SCRIPT_WITH_SITE.format(python=python, site_root=str(site_root))


POLKIT_POLICY = build_polkit_policy()


def install_privileged_helper(
    *,
    prefix: Path | None = None,
    dev_mode: bool = False,
) -> dict[str, object]:
    """Install helper script and polkit policy (requires root)."""
    if os.geteuid() != 0:
        return {
            "ok": False,
            "message": "Must run as root (sudo oyst-cli install-privileged-helper)",
            "helper_path": "",
            "polkit_path": "",
            "policy_version": POLICY_VERSION,
        }

    helper_dir = prefix / "lib" / "oysterav" if prefix else HELPER_DIR
    helper_path = helper_dir / "oyst-helper"
    polkit_path = (
        prefix / "share" / "polkit-1" / "actions" / "io.github.asafelobotomy.policy"
        if prefix
        else POLKIT_PATH
    )

    allow_untrusted = prefix is not None or dev_mode

    try:
        helper_dir.mkdir(parents=True, exist_ok=True)
        helper_path.write_text(
            _helper_script_text(allow_untrusted_python=allow_untrusted),
            encoding="utf-8",
        )
        helper_path.chmod(helper_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if prefix is None:
            bin_link = Path("/usr/bin/oyst-helper")
            bin_link.parent.mkdir(parents=True, exist_ok=True)
            if bin_link.is_symlink() or bin_link.exists():
                bin_link.unlink()
            bin_link.symlink_to(helper_path)
            legacy_bin = Path("/usr/local/bin/oyst-helper")
            if legacy_bin.is_symlink() or legacy_bin.exists():
                try:
                    legacy_bin.unlink()
                except OSError:
                    pass
        polkit_path.parent.mkdir(parents=True, exist_ok=True)
        polkit_path.write_text(build_polkit_policy(), encoding="utf-8")
        if shutil.which("polkitd") and prefix is None:
            run_command(["systemctl", "reload", "polkit"], timeout=15)
    except OSError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "helper_path": str(helper_path),
            "polkit_path": str(polkit_path),
            "policy_version": POLICY_VERSION,
        }

    migrate_result: dict[str, object] | None = None
    try:
        migrate_result = migrate_grant_on_helper_install(prefix=prefix)
    except (OSError, ValueError):
        migrate_result = None

    payload: dict[str, object] = {
        "ok": True,
        "message": (
            "Installed oyst-helper and polkit policy"
            + (
                " (dev mode: helper embeds this checkout; not for production hosts)"
                if dev_mode
                else ""
            )
        ),
        "helper_path": str(helper_path),
        "polkit_path": str(polkit_path),
        "policy_version": POLICY_VERSION,
        "actions": list(POLKIT_ACTION_IDS),
        "dev_mode": dev_mode,
    }
    if migrate_result is not None:
        payload["grant_migrated"] = migrate_result
    return payload


def resolve_installed_helper_path() -> Path | None:
    """Prefer /usr/lib, then legacy /usr/local/lib, for an installed oyst-helper."""
    for candidate in (HELPER_PATH, HELPER_PATH_LEGACY):
        if candidate.is_file():
            return candidate
    return None


def helper_status() -> dict[str, object]:
    helper = resolve_installed_helper_path()
    polkit_present = False
    try:
        polkit_present = POLKIT_PATH.is_file()
    except OSError:
        polkit_present = False
    installed = helper is not None and polkit_present
    actions_present: list[str] = []
    policy_text = ""
    if polkit_present:
        try:
            policy_text = POLKIT_PATH.read_text(encoding="utf-8")
        except OSError:
            policy_text = ""
        actions_present = [aid for aid in POLKIT_ACTION_IDS if aid in policy_text]
    import_ok: bool | None = None
    if helper is not None:
        try:
            proc = subprocess.run(
                [str(helper), "systemctl", "enable-now", "__oysterav_probe__"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                cwd="/",
            )
            # Probe unit is invalid; success is getting past import into argv validation.
            err = (proc.stderr or proc.stdout or "").lower()
            import_ok = "no module named 'oyst_core'" not in err
        except (OSError, subprocess.TimeoutExpired):
            import_ok = False
    return {
        "installed": installed,
        "helper_path": str(helper) if helper else str(HELPER_PATH),
        "polkit_path": str(POLKIT_PATH),
        "policy_version": POLICY_VERSION,
        "actions": list(POLKIT_ACTION_IDS),
        "actions_present": actions_present,
        "policy_current": bool(actions_present) and set(actions_present) == set(POLKIT_ACTION_IDS),
        "import_ok": import_ok,
    }
