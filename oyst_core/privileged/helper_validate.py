"""Package/scanner/run/install-script validators for oyst-helper."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

ALLOWED_PACKAGE_MANAGERS = frozenset({"pacman", "dnf", "apt-get", "apt"})
ALLOWED_SCANNER_BINARIES = frozenset(
    {
        "rkhunter",
        "chkrootkit",
        "lynis",
        "unhide",
        "unhide-linux",
        "clamonacc",
    }
)
PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$")
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
RKHUNTER_FLAGS = frozenset({"--update", "--propupd", "--versioncheck", "--check", "--sk", "--rwo"})
UNHIDE_MODES = frozenset({"sys", "brute", "quick", "check", "fork", "proc", "reverse"})
CLAMONACC_FLAGS = frozenset({"--foreground", "-F", "--fdpass"})


def _validate_package_name(name: str) -> str:
    cleaned = name.strip()
    if not PACKAGE_NAME_RE.match(cleaned):
        raise ValueError(f"invalid package name: {name}")
    return cleaned


def _validate_username(name: str) -> str:
    cleaned = name.strip()
    if not USERNAME_RE.match(cleaned):
        raise ValueError(f"invalid username: {name}")
    return cleaned


def _validate_package_manager_argv(base: str, argv: Sequence[str]) -> list[str]:
    """Allow only install/sync shapes with validated package names."""
    args = list(argv[1:])
    if base == "pacman":
        if not args or args[0] not in ("-S", "-Sy"):
            raise ValueError("pacman only allows -S/-Sy install")
        sync_flag = args[0]
        rest = args[1:]
        if "--noconfirm" not in rest:
            raise ValueError("pacman install requires --noconfirm")
        packages = [a for a in rest if a != "--noconfirm"]
        if not packages:
            raise ValueError("pacman install requires package names")
        return [base, sync_flag, "--noconfirm", *(_validate_package_name(p) for p in packages)]
    if base == "dnf":
        if len(args) < 2 or args[0] != "install" or args[1] != "-y":
            raise ValueError("dnf only allows: install -y <packages>")
        packages = args[2:]
        if not packages:
            raise ValueError("dnf install requires package names")
        return [base, "install", "-y", *(_validate_package_name(p) for p in packages)]
    if base in ("apt-get", "apt"):
        if len(args) < 2 or args[0] != "install" or args[1] != "-y":
            raise ValueError(f"{base} only allows: install -y <packages>")
        packages = args[2:]
        if not packages:
            raise ValueError(f"{base} install requires package names")
        return [base, "install", "-y", *(_validate_package_name(p) for p in packages)]
    raise ValueError(f"unsupported package manager: {base}")


def _validate_scanner_argv(base: str, argv: Sequence[str]) -> list[str]:
    """Allow constrained privileged scanner invocations (basename + known flags)."""
    # Preserve caller path (runtime private binaries) but validate by basename.
    binary = argv[0]
    args = list(argv[1:])
    if base == "rkhunter":
        if not args:
            raise ValueError("rkhunter requires an action flag")
        for flag in args:
            if flag not in RKHUNTER_FLAGS:
                raise ValueError(f"rkhunter flag not allowlisted: {flag}")
        if args[0] not in ("--update", "--propupd", "--versioncheck", "--check"):
            raise ValueError("rkhunter action not allowlisted")
        return [binary, *args]
    if base == "chkrootkit":
        if args:
            raise ValueError("chkrootkit takes no arguments")
        return [binary]
    if base == "lynis":
        if len(args) < 2 or args[0] != "audit" or args[1] != "system":
            raise ValueError("lynis only allows: audit system ...")
        allowed_opts = {"--no-colors", "--quick", "--profile"}
        i = 2
        out = [binary, "audit", "system"]
        while i < len(args):
            opt = args[i]
            if opt not in allowed_opts:
                raise ValueError(f"lynis option not allowlisted: {opt}")
            out.append(opt)
            if opt == "--profile":
                i += 1
                if i >= len(args):
                    raise ValueError("lynis --profile requires a path")
                profile = Path(args[i])
                if not profile.is_absolute() or ".." in profile.parts:
                    raise ValueError("lynis profile must be an absolute path")
                out.append(str(profile))
            i += 1
        return out
    if base in ("unhide", "unhide-linux"):
        if len(args) != 1 or args[0] not in UNHIDE_MODES:
            raise ValueError("unhide requires a single allowlisted mode")
        return [binary, args[0]]
    if base == "clamonacc":
        return _validate_clamonacc_argv(binary, args)
    raise ValueError(f"scanner not allowlisted: {base}")


def _validate_clamonacc_argv(binary: str, args: Sequence[str]) -> list[str]:
    """Allow --foreground (required), optional --fdpass and --include-list=ABS_PATH."""
    if "--foreground" not in args and "-F" not in args:
        raise ValueError("clamonacc requires --foreground")
    out: list[str] = [binary]
    for arg in args:
        if arg in ("--foreground", "-F", "--fdpass"):
            out.append("--foreground" if arg == "-F" else arg)
            continue
        if arg.startswith("--include-list="):
            path = Path(arg.split("=", 1)[1])
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("clamonacc --include-list must be an absolute path")
            if any(ch in str(path) for ch in (";", "|", "&", "$", "`", "\n", "\r")):
                raise ValueError("clamonacc --include-list path contains disallowed characters")
            if not path.is_file():
                raise ValueError(f"clamonacc include list not found: {path}")
            out.append(f"--include-list={path}")
            continue
        raise ValueError(f"clamonacc flag not allowlisted: {arg}")
    return out


def _validate_run_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ValueError("empty command")
    base = os.path.basename(argv[0])
    if base in ALLOWED_PACKAGE_MANAGERS:
        return _validate_package_manager_argv(base, argv)
    if base in ALLOWED_SCANNER_BINARIES:
        return _validate_scanner_argv(base, argv)
    if base == "loginctl":
        if len(argv) != 3 or argv[1] not in ("enable-linger", "disable-linger"):
            raise ValueError(f"loginctl action not allowed: {' '.join(argv[1:])}")
        return ["loginctl", argv[1], _validate_username(argv[2])]
    raise ValueError(f"command not allowlisted: {base}")


def _validate_install_script(path: str) -> Path:
    script = Path(path).resolve()
    if script.name != "install.sh":
        raise ValueError("only install.sh scripts are allowed")
    if not script.is_file():
        raise ValueError(f"install script not found: {script}")
    parent_name = script.parent.name
    if not parent_name.startswith("maldetect-"):
        raise ValueError("install.sh must live in a maldetect-* directory")
    if not any(p.startswith("oyst-maldet-") for p in script.parts):
        raise ValueError("install.sh must be under an oyst-maldet-* temp extract")
    under_tmp = False
    for root in (Path("/tmp").resolve(), Path("/var/tmp").resolve()):
        try:
            script.relative_to(root)
            under_tmp = True
            break
        except ValueError:
            continue
    if not under_tmp:
        raise ValueError("install.sh must be under /tmp or /var/tmp")
    return script
