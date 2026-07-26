"""Adversarial corpora for sealed scanners, install tarballs, and concert gates."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged.helper_concert import run_concert
from oyst_core.privileged.helper_fw_lifecycle import _family_install_argv
from oyst_core.privileged.helper_install_script import (
    _tarball_path_ok,
    open_maldet_tarball_fd,
    seal_and_run_install_tarball,
)
from oyst_core.privileged.helper_scan_concert import _validate_job_id
from oyst_core.privileged.helper_sealed_scanner import validate_sealed_source
from tests.test_security.corpora import BAD_SHA256, CONCERT_ABUSE_CASES, PATH_TRAVERSAL, Case

pytestmark = pytest.mark.security

_CONCERT_RECIPE_CASES = tuple(c for c in CONCERT_ABUSE_CASES if c.surface == "helper_concert")
_INSTALL_PKG_CASES = tuple(c for c in CONCERT_ABUSE_CASES if c.surface == "helper_fw_install")


@pytest.mark.parametrize(
    ("path", "basename", "sha"),
    [
        ("/tmp/evil", "rkhunter", "a" * 64),
        ("/home/u/.local/share/oysterav/runtime/x/bin/rkhunter", "bash", "a" * 64),
        (
            "/home/u/.local/share/oysterav/runtime/x/bin/rkhunter",
            "rkhunter",
            BAD_SHA256[1],
        ),
        (
            "/home/u/.local/share/oysterav/runtime/x/bin/chkrootkit",
            "rkhunter",
            "a" * 64,
        ),
        *[(p, "rkhunter", "a" * 64) for p in PATH_TRAVERSAL],
    ],
)
def test_validate_sealed_source_rejects(path: str, basename: str, sha: str) -> None:
    with pytest.raises(ValueError):
        validate_sealed_source(path, basename, sha)


def test_validate_sealed_source_accepts_runtime_shape() -> None:
    homeish = Path("/home/tester/.local/share/oysterav/runtime/pack/bin/rkhunter")
    assert validate_sealed_source(str(homeish), "rkhunter", "a" * 64) == homeish


@pytest.mark.parametrize("sha", BAD_SHA256)
def test_open_maldet_tarball_rejects_bad_sha(tmp_path: Path, sha: str) -> None:
    with pytest.raises(ValueError):
        open_maldet_tarball_fd(str(tmp_path / "x.tar.gz"), sha)


def test_tarball_path_ok_rejects() -> None:
    with pytest.raises(ValueError):
        _tarball_path_ok(Path("/home/u/evil.tar.gz"))
    with pytest.raises(ValueError):
        _tarball_path_ok(Path("/tmp/oyst-maldet-x/notatar"))
    with pytest.raises(ValueError):
        _tarball_path_ok(Path("/var/tmp/wrongprefix/pkg.tar.gz"))


@pytest.mark.parametrize(
    "job_id",
    ["", "short", "../x", "zzzz", "a" * 65, "job;id", "job id"],
)
def test_validate_job_id_rejects(job_id: str) -> None:
    with pytest.raises(ValueError):
        _validate_job_id(job_id)


def test_validate_job_id_accepts_uuid_like() -> None:
    assert _validate_job_id("abcdef01-2345-6789-abcd-ef0123456789")


@pytest.mark.parametrize("case", _CONCERT_RECIPE_CASES, ids=lambda c: c.id)
def test_run_concert_rejects_unknown_recipe(case: Case) -> None:
    assert case.expect.kind == "value_error"
    with pytest.raises(ValueError):
        run_concert(list(case.payload))  # type: ignore[arg-type]


@pytest.mark.parametrize("case", _INSTALL_PKG_CASES, ids=lambda c: c.id)
def test_family_install_rejects_traversal_packages(case: Case) -> None:
    assert case.expect.kind == "value_error"
    family, pkgs = case.payload  # type: ignore[misc]
    with pytest.raises(ValueError):
        _family_install_argv(family, pkgs)


def test_run_concert_dispatches_known_recipe() -> None:
    with patch(
        "oyst_core.privileged.helper_concert.run_setup_concert",
        return_value=0,
    ) as setup:
        assert run_concert(["--recipe=setup", "--flag"]) == 0
    setup.assert_called_once()


def test_seal_tarball_uses_fd_bytes_not_path_after_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A-02-R: sealed extract uses verified fd bytes after unlink+recreate at path."""
    import hashlib
    import os
    import shutil
    import tarfile
    import uuid

    root = Path("/tmp") / f"oyst-maldet-{uuid.uuid4().hex[:12]}"  # nosec B108
    root.mkdir(parents=True)
    mal_dir = root / "maldetect-1.0"
    mal_dir.mkdir()
    (mal_dir / "install.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    tarball = root / "maldetect-current.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(mal_dir, arcname="maldetect-1.0")
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    real_open = open_maldet_tarball_fd

    def _replace_after_open(path: str, expected: str) -> int:
        fd = real_open(path, expected)
        os.unlink(path)
        evil = root / "evil"
        evil.mkdir(exist_ok=True)
        (evil / "install.sh").write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
        with tarfile.open(path, "w:gz") as archive:
            archive.add(evil, arcname="maldetect-evil")
        return fd

    monkeypatch.setattr(
        "oyst_core.privileged.helper_install_script.open_maldet_tarball_fd",
        _replace_after_open,
    )
    try:
        with (
            patch(
                "oyst_core.privileged.helper_install_script.resolve_trusted_binary",
                return_value="/bin/bash",
            ),
            patch(
                "oyst_core.privileged.helper_install_script.subprocess.run",
                return_value=type("R", (), {"returncode": 0})(),
            ) as run,
        ):
            assert seal_and_run_install_tarball(str(tarball), digest) == 0
        assert "maldetect-1.0" in run.call_args[0][0][1]
        assert "maldetect-evil" not in run.call_args[0][0][1]
    finally:
        shutil.rmtree(root, ignore_errors=True)
