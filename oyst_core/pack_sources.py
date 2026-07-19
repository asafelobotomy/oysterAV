"""Source-based pack installers (tarball, etc.)."""

from __future__ import annotations

import getpass
import hashlib
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

from oyst_core.privileged.helper import run_privileged_install_script
from oyst_core.privileged.runner import CommandResult

MALDET_URL = "https://www.rfxn.com/downloads/maldetect-current.tar.gz"
# In-repo pin (fail-closed). Update via PR after reviewing a new upstream release.
MALDET_SHA256 = "76f1d260dac5e0bb3ca487f8d3e119655196de87b08ec89dfd73155e083feb5d"


def _download(url: str, dest: Path) -> None:
    with urlopen(url, timeout=120) as response:  # noqa: S310 — fixed upstream URL
        dest.write_bytes(response.read())


def _verify_sha256(file_path: Path, expected: str) -> bool:
    digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
    return digest == expected.lower()


def install_maldet_tarball() -> CommandResult:
    """Download LMD tarball, verify in-repo SHA-256, and run install.sh with helper."""
    work = Path(tempfile.mkdtemp(prefix="oyst-maldet-"))
    try:
        tarball = work / "maldetect-current.tar.gz"
        _download(MALDET_URL, tarball)
        if not _verify_sha256(tarball, MALDET_SHA256):
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

        install_dirs = list(extract_dir.glob("maldetect-*"))
        if not install_dirs:
            return CommandResult(1, "", "Could not find maldetect directory in tarball")
        install_sh = install_dirs[0] / "install.sh"
        if not install_sh.is_file():
            return CommandResult(1, "", "install.sh not found in tarball")

        install_sh.chmod(0o755)
        from oyst_core.runtime.manifest import is_full_mode

        if is_full_mode():
            return _install_maldet_to_runtime(install_dirs[0])
        res = run_privileged_install_script(str(install_sh))
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
        return CommandResult(0, f"Installed maldet to {dest}", "")
    except OSError as exc:
        return CommandResult(1, "", str(exc))


def configure_maldet_clamav(prefix: Path | None = None) -> bool:
    """Tune maldet conf for oysterAV desktop/runtime use.

    Enables ClamAV layering (``scan_clamscan``) and non-root access
    (``scan_user_access``) so signature updates and scans work without root.
    Returns True if the config file changed.
    """
    if prefix is None:
        conf = Path("/usr/local/maldetect/conf.maldet")
    else:
        conf = prefix / "conf.maldet"
    if not conf.is_file():
        return False
    try:
        text = conf.read_text(encoding="utf-8")
        original = text
        text = text.replace('scan_clamscan="0"', 'scan_clamscan="1"')
        text = text.replace("scan_clamscan=0", "scan_clamscan=1")
        text = text.replace('scan_user_access="0"', 'scan_user_access="1"')
        text = text.replace("scan_user_access=0", "scan_user_access=1")
        if text != original:
            conf.write_text(text, encoding="utf-8")
            return True
    except OSError:
        return False
    return False


def ensure_maldet_pub_paths(binary: str) -> tuple[bool, str]:
    """Create per-user pub paths required when scan_user_access=1.

    LMD's ``--mkpubpaths`` runs after ``prerun``, which already requires those
    paths for non-root — so oysterAV creates them directly under the install's
    ``pub/<user>/`` tree (same layout as upstream ``--mkpubpaths``).
    """
    inspath = Path(binary).resolve().parent
    pub = inspath / "pub"
    user = getpass.getuser()
    user_dir = pub / user
    try:
        pub.mkdir(parents=True, exist_ok=True)
        os.chmod(pub, 0o711)
        for sub in ("quar", "sess", "tmp"):
            (user_dir / sub).mkdir(parents=True, exist_ok=True)
        event_log = user_dir / "event_log"
        if not event_log.exists():
            event_log.touch()
        os.chmod(user_dir, 0o750)
        for sub in ("quar", "sess", "tmp"):
            os.chmod(user_dir / sub, 0o750)
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
