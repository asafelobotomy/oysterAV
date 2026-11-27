"""Source-based pack installers (tarball, etc.)."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from oyst_core.net_util import DEFAULT_MAX_DOWNLOAD_BYTES, download_to_path
from oyst_core.privileged.helper import run_privileged_install_script
from oyst_core.privileged.pins import MALDET_SHA256
from oyst_core.privileged.runner import CommandResult, run_command
from oyst_core.privileged.safe_write import write_text_nofollow
from oyst_core.scan_excludes import default_scan_exclude_dirs
from oyst_core.schedule_linger import current_username

MALDET_VERSION = "2.0.1"
# Versioned GitHub release asset: rfxn.com's ``maldetect-current`` still serves 1.6.6 and
# changes on every upstream release, which would break the in-repo SHA-256 pin
# (oyst_core.privileged.pins, fail-closed). LMD 2.x tarballs unpack to ``maldet-<ver>/``.
MALDET_URL = (
    "https://github.com/rfxn/linux-malware-detect/releases/download/"
    f"v{MALDET_VERSION}/maldet-{MALDET_VERSION}.tar.gz"
)
# Top-level folder of an LMD tarball: ``maldet-<ver>`` (2.x) or ``maldetect-<ver>`` (1.x).
MALDET_EXTRACT_GLOBS = ("maldet-*", "maldetect-*")
MALDET_MAX_BYTES = 32 * 1024 * 1024


def _download(url: str, dest: Path, *, max_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES) -> None:
    """Stream ``url`` to ``dest`` (https-only, size-capped, partial file removed)."""
    download_to_path(url, dest, timeout=120, max_bytes=max_bytes)


def _verify_sha256(file_path: Path, expected: str) -> bool:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest() == expected.lower()


def stage_maldet_install_script() -> tuple[str, str, str, Path] | CommandResult:
    """Download/verify maldet tarball; return (tarball, tarball_sha, install_sh, work).

    ``install_sh`` is for full-mode runtime copy only. Privileged installs must
    pass the tarball path + ``MALDET_SHA256`` into the helper (A-02).
    Caller must ``shutil.rmtree(work_dir)`` after the privileged concert finishes.
    On failure returns a ``CommandResult``.
    """
    work = Path(tempfile.mkdtemp(prefix="oyst-maldet-"))
    try:
        tarball = work / f"maldet-{MALDET_VERSION}.tar.gz"
        _download(MALDET_URL, tarball, max_bytes=MALDET_MAX_BYTES)
        if not _verify_sha256(tarball, MALDET_SHA256):
            shutil.rmtree(work, ignore_errors=True)
            return CommandResult(
                1,
                "",
                "Checksum verification failed for maldetect tarball "
                "(in-repo pin mismatch; update MALDET_SHA256 after review)",
            )
        extract_dir = work / "extract"
        extract_dir.mkdir()
        with tarfile.open(tarball, "r:gz") as archive:
            archive.extractall(extract_dir, filter="data")
        install_dirs = [d for g in MALDET_EXTRACT_GLOBS for d in sorted(extract_dir.glob(g))]
        if not install_dirs:
            shutil.rmtree(work, ignore_errors=True)
            return CommandResult(1, "", "Could not find maldetect directory in tarball")
        install_sh = install_dirs[0] / "install.sh"
        if not install_sh.is_file():
            shutil.rmtree(work, ignore_errors=True)
            return CommandResult(1, "", "install.sh not found in tarball")
        install_sh.chmod(0o755)
        return str(tarball), MALDET_SHA256, str(install_sh), work
    except (OSError, ValueError, tarfile.TarError) as exc:
        shutil.rmtree(work, ignore_errors=True)
        return CommandResult(1, "", str(exc))


def install_maldet_tarball() -> CommandResult:
    """Download LMD tarball, verify in-repo SHA-256, and run install.sh with helper."""
    from oyst_core.runtime.manifest import is_full_mode

    staged = stage_maldet_install_script()
    if isinstance(staged, CommandResult):
        return staged
    tarball, tarball_sha, install_sh, work = staged
    try:
        if is_full_mode():
            source_dir = Path(install_sh).parent
            return _install_maldet_to_runtime(source_dir)
        res = run_privileged_install_script(
            tarball,
            expected_sha256=tarball_sha,
        )
        if res.returncode == 0:
            _configure_maldet_clamav(None)
        return res
    except OSError as exc:
        return CommandResult(1, "", str(exc))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _install_maldet_to_runtime(source_dir: Path) -> CommandResult:
    """Copy maldet tree into runtime prefix without root."""
    from oyst_core.runtime.bundles.scanners import install_maldet_runtime_tree

    try:
        dest = install_maldet_runtime_tree(source_dir)
        _configure_maldet_clamav(dest)
        # Tarballs ship no signatures (install.sh fetches them for system installs); without
        # this every runtime scan aborted on "required signature file not found".
        sig = run_command([str(dest / "maldet"), "-u"], timeout=600)
        if sig.returncode != 0:
            return CommandResult(
                0, f"Installed maldet to {dest}; signature update failed (run: maldet -u)", ""
            )
        return CommandResult(0, f"Installed maldet to {dest} with signatures", "")
    except OSError as exc:
        return CommandResult(1, "", str(exc))


def configure_maldet_clamav(prefix: Path | None = None) -> bool:
    """Tune maldet conf for oysterAV desktop/runtime use.

    Turns off LMD's ClamAV stage (``scan_clamscan``) and turns on non-root access
    (``scan_user_access``) so signature updates and scans work without root.
    Adds oysterAV's vault and maldet's own sigs/pub trees to LMD's ``ignore_paths``
    *file* (one path per line, next to conf.maldet). ``ignore_paths`` in conf.maldet
    is the path of that file: older oysterAV wrote the paths themselves there, which
    made LMD's ``grep -vf`` fail and every scan run on an empty file list, so that
    line is removed. Returns True if anything changed.
    """
    conf = Path("/usr/local/maldetect/conf.maldet") if prefix is None else prefix / "conf.maldet"
    if not conf.is_file():
        return False
    changed = False
    try:
        text = conf.read_text(encoding="utf-8")
        original = text
        # LMD's own engine only: oysterAV already runs ClamAV on the same paths, and LMD 2.0.1's
        # user-mode clamscan stage loads nothing (its temp .ndb name has a random suffix that
        # clamscan rejects as "unknown extension"), so layering only doubled the work.
        text = re.sub(r"^scan_clamscan=.*$", 'scan_clamscan="0"', text, flags=re.MULTILINE)
        text = text.replace('scan_user_access="0"', 'scan_user_access="1"')
        text = text.replace("scan_user_access=0", "scan_user_access=1")
        text = re.sub(r"^ignore_paths=.*\n?", "", text, flags=re.MULTILINE)
        if text != original:
            write_text_nofollow(conf, text, mode=0o644)
            changed = True
        changed = _merge_maldet_ignore_paths(conf.parent / "ignore_paths") or changed
    except OSError:
        return changed
    return changed


def _merge_maldet_ignore_paths(path: Path) -> bool:
    """Add oysterAV's exclusions to LMD's ignore_paths file, keeping the user's lines."""
    try:
        current = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    except OSError:
        current = []
    lines = [line for line in current if line.strip()]
    missing = [p for p in default_scan_exclude_dirs() if p not in lines]
    if not missing:
        return False
    write_text_nofollow(path, "\n".join([*lines, *missing]) + "\n", mode=0o644)
    return True


def ensure_maldet_pub_paths(binary: str) -> tuple[bool, str]:
    """Create per-user pub paths required when scan_user_access=1.

    LMD's ``--mkpubpaths`` runs after ``prerun``, which already requires those
    paths for non-root — so oysterAV creates them directly under the install's
    ``pub/<user>/`` tree (same layout as upstream ``--mkpubpaths``).
    """
    inspath = Path(binary).resolve().parent
    pub = inspath / "pub"
    user = current_username()
    user_dir = pub / user
    try:
        pub.mkdir(parents=True, exist_ok=True)
        os.chmod(pub, 0o711)  # maldet pub needs o+x for path traversal  # nosec B103
        for sub in ("quar", "sess", "tmp"):
            (user_dir / sub).mkdir(parents=True, exist_ok=True)
        event_log = user_dir / "event_log"
        if not event_log.exists():
            event_log.touch()
        os.chmod(user_dir, 0o750)  # owner+group only  # nosec B103
        for sub in ("quar", "sess", "tmp"):
            os.chmod(user_dir / sub, 0o750)  # owner+group only  # nosec B103
        os.chmod(event_log, 0o640)
    except OSError as exc:
        return False, str(exc)
    return True, f"ensured {user_dir}"


def _configure_maldet_clamav(prefix: Path | None = None) -> None:
    configure_maldet_clamav(prefix)
    if prefix is not None:
        binary = prefix / "maldet"
        if binary.is_file():
            ensure_maldet_pub_paths(str(binary))
    else:
        for candidate in ("/usr/local/sbin/maldet", "/usr/sbin/maldet", "/usr/bin/maldet"):
            if Path(candidate).is_file():
                ensure_maldet_pub_paths(candidate)
                break
