#!/usr/bin/env python3
"""Sync VERSION into pyproject, package inits, metainfo, and distro packaging.

VERSION is the single source of truth for the application release version.
RUNTIME_VERSION in oyst_core.runtime.manifest is intentionally separate.

Synced / checked: pyproject.toml, package ``__version__``, Flatpak metainfo
(<release>; screenshots stay on main because older tags lack some images), Arch PKGBUILD and
.SRCINFO (rendered), RPM spec ``Version:``, Debian changelog top entry, and the
Flathub manifest tag archive (URL + sha256 copied from the rendered PKGBUILD).

Usage:
  python scripts/sync_version.py                  # write synced files
  python scripts/sync_version.py --check          # exit 1 on drift
  python scripts/sync_version.py --check --strict-sha256
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_INITS = (
    ROOT / "oyst_core" / "__init__.py",
    ROOT / "oysterav" / "__init__.py",
)
FLATPAK_DIR = ROOT / "packaging" / "oysterav" / "flatpak"
METAINFO = FLATPAK_DIR / "io.github.asafelobotomy.OysterAV.metainfo.xml"
FLATHUB_MANIFEST = FLATPAK_DIR / "flathub" / "io.github.asafelobotomy.OysterAV.yml"
PKGBUILD = ROOT / "packaging" / "arch" / "PKGBUILD"
SRCINFO = ROOT / "packaging" / "arch" / ".SRCINFO"
RPM_SPEC = ROOT / "packaging" / "rpm" / "oysterav.spec"
DEB_CHANGELOG = ROOT / "packaging" / "debian" / "changelog"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[a-zA-Z0-9.+\-]+)?$")
RELEASE_TAG_RE = re.compile(r'(<release\s+version=")([^"]*)("\s+date=")([^"]*)("\s*/>)')
PKGVER_RE = re.compile(r"(?m)^pkgver=(.*)$")
PKGBUILD_SHA_RE = re.compile(r"(?m)^sha256sums=\('([^']*)'\)")
SRCINFO_PKGVER_RE = re.compile(r"(?m)^\s*pkgver = (.*)$")
SRCINFO_SHA_RE = re.compile(r"(?m)^\s*sha256sums = (.*)$")
RPM_VERSION_RE = re.compile(r"(?m)^(Version:[ \t]*)(\S+)[ \t]*$")
DEB_TOP_RE = re.compile(r"\A(oysterav \()([^)-]+)(-[^)]*)?(\))")
FLATHUB_TAG_RE = re.compile(
    r"(url: https://github\.com/asafelobotomy/oysterAV/archive/refs/tags/v)([^\s/]+)(\.tar\.gz\n"
    r"\s*sha256: )([0-9a-fA-F]+|SKIP)"
)


def read_version() -> str:
    text = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not text or not VERSION_RE.match(text):
        raise SystemExit(f"Invalid VERSION in {VERSION_FILE}: {text!r}")
    return text


def _sub_one(pattern: re.Pattern[str], repl: str, content: str, what: str) -> str:
    updated, n = pattern.subn(repl, content, count=1)
    if n != 1:
        raise SystemExit(f"Could not find {what}")
    return updated


def _replace_pyproject(version: str, content: str) -> str:
    pat = re.compile(r'(?m)^version\s*=\s*"[^"]*"')
    return _sub_one(pat, f'version = "{version}"', content, "project version in pyproject.toml")


def _replace_init(version: str, content: str) -> str:
    pat = re.compile(r'(?m)^__version__\s*=\s*"[^"]*"')
    return _sub_one(pat, f'__version__ = "{version}"', content, "__version__ in package init")


def _replace_metainfo(version: str, content: str, *, today: str | None = None) -> str:
    """Bump <release>; the date changes only when the version changes."""
    match = RELEASE_TAG_RE.search(content)
    if not match:
        raise SystemExit(f"No <release version=.../> in {METAINFO}")
    if match.group(2) != version:
        stamp = today or date.today().isoformat()
        content = (
            content[: match.start()]
            + f"{match.group(1)}{version}{match.group(3)}{stamp}{match.group(5)}"
            + content[match.end() :]
        )
    return content


def _replace_rpm(version: str, content: str) -> str:
    return _sub_one(RPM_VERSION_RE, rf"\g<1>{version}", content, "Version: in RPM spec")


def _replace_deb_changelog(version: str, content: str) -> str:
    match = DEB_TOP_RE.match(content)
    if not match:
        raise SystemExit(f"Could not parse top entry of {DEB_CHANGELOG}")
    if match.group(2) == version:
        return content
    return f"{match.group(1)}{version}-1{match.group(4)}" + content[match.end() :]


def _replace_flathub(version: str, content: str, sha256: str | None) -> str:
    match = FLATHUB_TAG_RE.search(content)
    if not match:
        raise SystemExit(f"Could not find tag archive source in {FLATHUB_MANIFEST}")
    new_sha = sha256 if sha256 and sha256 != "SKIP" else match.group(4)
    return (
        content[: match.start()]
        + f"{match.group(1)}{version}{match.group(3)}{new_sha}"
        + content[match.end() :]
    )


def _search(pattern: re.Pattern[str], path: Path, group: int = 1) -> str | None:
    if not path.is_file():
        return None
    match = pattern.search(path.read_text(encoding="utf-8"))
    return match.group(group).strip() if match else None


def pkgbuild_sha256() -> str | None:
    return _search(PKGBUILD_SHA_RE, PKGBUILD)


def current_versions() -> dict[str, str]:
    py = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]*)"', py)
    if not m:
        raise SystemExit("pyproject.toml missing version")
    found: dict[str, str] = {"pyproject.toml": m.group(1)}
    for path in PACKAGE_INITS:
        im = re.search(r'(?m)^__version__\s*=\s*"([^"]*)"', path.read_text(encoding="utf-8"))
        if not im:
            raise SystemExit(f"{path} missing __version__")
        found[_rel(path)] = im.group(1)
    meta = METAINFO.read_text(encoding="utf-8")
    mm = RELEASE_TAG_RE.search(meta)
    if not mm:
        raise SystemExit(f"{METAINFO} missing <release version=.../>")
    found[_rel(METAINFO)] = mm.group(2)
    optional = (
        (PKGBUILD, PKGVER_RE, 1, ""),
        (SRCINFO, SRCINFO_PKGVER_RE, 1, ""),
        (RPM_SPEC, RPM_VERSION_RE, 2, ""),
        (DEB_CHANGELOG, DEB_TOP_RE, 2, ""),
        (FLATHUB_MANIFEST, FLATHUB_TAG_RE, 2, " tag"),
    )
    for path, pattern, group, suffix in optional:
        if not path.is_file():
            continue
        value = _search(pattern, path, group)
        found[_rel(path) + suffix] = value if value is not None else "<unparseable>"
    return found


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def _render_arch_pkgbuild() -> None:
    script = ROOT / "scripts" / "render_arch_pkgbuild.sh"
    subprocess.run(["bash", str(script)], check=True, cwd=ROOT)


def _rewrite(path: Path, fn: Callable[[str], str], changed: list[Path]) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    new_text = fn(text)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        changed.append(path)


def sync(version: str) -> list[Path]:
    changed: list[Path] = []
    _rewrite(PYPROJECT, lambda t: _replace_pyproject(version, t), changed)
    for path in PACKAGE_INITS:
        _rewrite(path, lambda t: _replace_init(version, t), changed)
    _rewrite(METAINFO, lambda t: _replace_metainfo(version, t), changed)
    _rewrite(RPM_SPEC, lambda t: _replace_rpm(version, t), changed)
    _rewrite(DEB_CHANGELOG, lambda t: _replace_deb_changelog(version, t), changed)
    before = {p: p.read_text(encoding="utf-8") if p.is_file() else "" for p in (PKGBUILD, SRCINFO)}
    _render_arch_pkgbuild()
    for path, old in before.items():
        if (path.read_text(encoding="utf-8") if path.is_file() else "") != old:
            changed.append(path)
    sha = pkgbuild_sha256()
    _rewrite(FLATHUB_MANIFEST, lambda t: _replace_flathub(version, t, sha), changed)
    return changed


def _tag_exists(version: str) -> bool:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "-q", "--verify", f"refs/tags/v{version}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0


def sha256_problems() -> tuple[list[str], bool]:
    """Return (problems, has_skip) for PKGBUILD/.SRCINFO/Flathub archive hashes."""
    problems: list[str] = []
    pkg_sha = pkgbuild_sha256()
    src_sha = _search(SRCINFO_SHA_RE, SRCINFO)
    has_skip = "SKIP" in {pkg_sha, src_sha}
    if has_skip:
        problems.append("packaging/arch PKGBUILD/.SRCINFO has sha256sums=SKIP")
    if pkg_sha and src_sha and pkg_sha != src_sha:
        problems.append(f"PKGBUILD sha256 {pkg_sha} != .SRCINFO sha256 {src_sha}")
    hub_sha = _search(FLATHUB_TAG_RE, FLATHUB_MANIFEST, 4)
    if pkg_sha and pkg_sha != "SKIP" and hub_sha and hub_sha != pkg_sha:
        problems.append(f"Flathub manifest sha256 {hub_sha} != PKGBUILD sha256 {pkg_sha}")
    return problems, has_skip


def check(version: str, *, strict_sha256: bool = False) -> None:
    found = current_versions()
    drift = {k: v for k, v in found.items() if v != version}
    if drift:
        lines = [f"VERSION is {version}, but these differ:"]
        lines.extend(f"  {k}: {v}" for k, v in drift.items())
        lines.append("Run: python scripts/sync_version.py")
        raise SystemExit("\n".join(lines))
    problems, has_skip = sha256_problems()
    hard = [p for p in problems if "SKIP" not in p]
    if has_skip and (strict_sha256 or _tag_exists(version)):
        # Tag v<version> exists, so the archive is published: SKIP is stale.
        hard = problems
    elif has_skip:
        print(
            "NOTE: sha256sums=SKIP allowed until tag v"
            f"{version} exists (then: REQUIRE_SHA256=1 bash scripts/render_arch_pkgbuild.sh)",
            file=sys.stderr,
        )
    if hard:
        raise SystemExit("sha256 check failed:\n  " + "\n  ".join(hard))
    print(f"OK: version {version} is in sync")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify VERSION matches every synced file (no writes)",
    )
    parser.add_argument(
        "--strict-sha256",
        action="store_true",
        help="With --check: fail on sha256sums=SKIP even before the release tag exists",
    )
    args = parser.parse_args(argv)
    version = read_version()
    if args.check:
        check(version, strict_sha256=args.strict_sha256)
        return 0
    changed = sync(version)
    if changed:
        for path in changed:
            print(f"updated {_rel(path)}")
    else:
        print(f"already in sync: {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
