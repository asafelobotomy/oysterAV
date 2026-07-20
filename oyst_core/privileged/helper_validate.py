"""Package/scanner/run/install-script validators for oyst-helper."""

from __future__ import annotations

import hashlib
import os
import re
import stat
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
_TRUSTED_PROFILE_PREFIXES = ("/usr/", "/etc/")
_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_TRUSTED_BIN_DIRS = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)


def _is_root_owned_file(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not (st.st_mode & 0o002)


def resolve_trusted_binary(name: str) -> str:
    """Map a basename to a root-owned absolute path under trusted prefixes."""
    base = os.path.basename(name)
    if not base or base in (".", ".."):
        raise ValueError(f"invalid binary name: {name!r}")
    for directory in _TRUSTED_BIN_DIRS:
        candidate = Path(directory) / base
        if candidate.is_file() and _is_root_owned_file(candidate):
            return str(candidate.resolve())
    raise ValueError(f"trusted binary not found for {base!r}")


def resolve_trusted_argv(argv: list[str]) -> list[str]:
    """Rewrite argv[0] to a trusted absolute path."""
    if not argv:
        return argv
    return [resolve_trusted_binary(argv[0]), *argv[1:]]


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
    """Allow constrained privileged scanner invocations (basename only, like PMs)."""
    args = list(argv[1:])
    if base == "rkhunter":
        if not args:
            raise ValueError("rkhunter requires an action flag")
        for flag in args:
            if flag not in RKHUNTER_FLAGS:
                raise ValueError(f"rkhunter flag not allowlisted: {flag}")
        if args[0] not in ("--update", "--propupd", "--versioncheck", "--check"):
            raise ValueError("rkhunter action not allowlisted")
        return [base, *args]
    if base == "chkrootkit":
        if args:
            raise ValueError("chkrootkit takes no arguments")
        return [base]
    if base == "lynis":
        if len(args) < 2 or args[0] != "audit" or args[1] != "system":
            raise ValueError("lynis only allows: audit system ...")
        allowed_opts = {"--no-colors", "--quick", "--profile"}
        i = 2
        out = [base, "audit", "system"]
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
                resolved = str(profile)
                if not resolved.startswith(_TRUSTED_PROFILE_PREFIXES):
                    raise ValueError("lynis profile must be under /usr or /etc")
                out.append(resolved)
            i += 1
        return out
    if base in ("unhide", "unhide-linux"):
        if len(args) != 1 or args[0] not in UNHIDE_MODES:
            raise ValueError("unhide requires a single allowlisted mode")
        return [base, args[0]]
    if base == "clamonacc":
        return _validate_clamonacc_argv(base, args)
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


def _install_script_path_ok(script: Path) -> None:
    if script.name != "install.sh":
        raise ValueError("only install.sh scripts are allowed")
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


def open_install_script_fd(path: str, expected_sha256: str) -> int:
    """Open install.sh with O_NOFOLLOW and verify SHA-256; return a seekable fd."""
    if not _SHA256_HEX_RE.fullmatch(expected_sha256 or ""):
        raise ValueError("install-script requires a 64-char sha256 hex digest")
    script = Path(path).resolve()
    _install_script_path_ok(script)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(script), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("install.sh must be a regular file")
        if st.st_mode & 0o002:
            raise ValueError("world-writable install.sh refused")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256.lower():
            raise ValueError("install.sh sha256 mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
    except Exception:
        os.close(fd)
        raise
    return fd


def _validate_install_script(path: str, expected_sha256: str | None = None) -> Path:
    """Path-shape validation (tests); production exec uses open_install_script_fd."""
    script = Path(path).resolve()
    _install_script_path_ok(script)
    if not script.is_file():
        raise ValueError(f"install script not found: {script}")
    if expected_sha256 is not None and not _SHA256_HEX_RE.fullmatch(expected_sha256):
        raise ValueError("install-script requires a 64-char sha256 hex digest")
    return script
