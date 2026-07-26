"""Tests for sealed maldet tarball install helper (A-02)."""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged.helper_install_script import (
    open_maldet_tarball_fd,
    seal_and_run_install_script,
    seal_and_run_install_tarball,
)


def _stage_tarball() -> tuple[Path, str]:
    root = Path("/tmp") / f"oyst-maldet-{uuid.uuid4().hex[:12]}"  # nosec B108
    root.mkdir(parents=True)
    mal_dir = root / "maldetect-1.0"
    mal_dir.mkdir()
    (mal_dir / "install.sh").write_text("#!/bin/sh\necho installed\n", encoding="utf-8")
    (mal_dir / "files").mkdir()
    (mal_dir / "files" / "payload").write_text("ok", encoding="utf-8")
    tarball = root / "maldetect-current.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(mal_dir, arcname="maldetect-1.0")
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    return tarball, digest


def test_open_maldet_tarball_fd_ok() -> None:
    tarball, digest = _stage_tarball()
    try:
        fd = open_maldet_tarball_fd(str(tarball), digest)
        os.close(fd)
    finally:
        shutil.rmtree(tarball.parent, ignore_errors=True)


def test_open_maldet_tarball_rejects_bad_hash() -> None:
    tarball, _digest = _stage_tarball()
    try:
        with pytest.raises(ValueError, match="sha256 mismatch"):
            open_maldet_tarball_fd(str(tarball), "0" * 64)
    finally:
        shutil.rmtree(tarball.parent, ignore_errors=True)


def test_legacy_install_sh_seal_raises() -> None:
    with pytest.raises(ValueError, match="tarball"):
        seal_and_run_install_script("/tmp/oyst-maldet-x/maldetect-1/install.sh", "a" * 64)


def test_seal_and_run_ignores_userspace_extract_mutation() -> None:
    """Helper re-extracts from tarball; sibling mutation in userspace extract is irrelevant."""
    tarball, digest = _stage_tarball()
    try:
        evil = tarball.parent / "extract" / "maldetect-1.0"
        evil.mkdir(parents=True)
        (evil / "install.sh").write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")

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
            rc = seal_and_run_install_tarball(str(tarball), digest)
        assert rc == 0
        cmd = run.call_args[0][0]
        assert "oyst-seal-" in cmd[1]
        assert cmd[1].endswith("install.sh")
        assert "extract/maldetect-1.0" in cmd[1]
        # cwd is sealed extract, not the evil userspace tree
        assert "oyst-seal-" in str(run.call_args.kwargs.get("cwd") or "")
        assert str(evil) not in cmd[1]
    finally:
        shutil.rmtree(tarball.parent, ignore_errors=True)


def test_seal_and_run_ignores_path_swap_after_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    """A-02-R: replacing the path with a new inode must not change sealed extract."""
    tarball, digest = _stage_tarball()
    try:
        real_open = open_maldet_tarball_fd

        def _open_then_replace(path: str, expected: str) -> int:
            fd = real_open(path, expected)
            # Unlink + recreate (new inode); open fd still holds verified bytes.
            os.unlink(path)
            evil_root = tarball.parent / "evil-tree"
            evil_root.mkdir(exist_ok=True)
            evil_mal = evil_root / "maldetect-evil"
            evil_mal.mkdir(exist_ok=True)
            (evil_mal / "install.sh").write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
            with tarfile.open(path, "w:gz") as archive:
                archive.add(evil_mal, arcname="maldetect-evil")
            return fd

        monkeypatch.setattr(
            "oyst_core.privileged.helper_install_script.open_maldet_tarball_fd",
            _open_then_replace,
        )
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
            rc = seal_and_run_install_tarball(str(tarball), digest)
        assert rc == 0
        cmd = run.call_args[0][0]
        assert "maldetect-1.0" in cmd[1]
        assert "maldetect-evil" not in cmd[1]
    finally:
        shutil.rmtree(tarball.parent, ignore_errors=True)


def test_seal_and_run_fails_closed_on_same_inode_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Truncating the same inode mid-flight must not extract attacker content."""
    tarball, digest = _stage_tarball()
    try:
        real_open = open_maldet_tarball_fd

        def _open_then_truncate(path: str, expected: str) -> int:
            fd = real_open(path, expected)
            with tarfile.open(path, "w:gz") as archive:
                evil = tarball.parent / "evil"
                evil.mkdir(exist_ok=True)
                (evil / "install.sh").write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")
                archive.add(evil, arcname="maldetect-evil")
            return fd

        monkeypatch.setattr(
            "oyst_core.privileged.helper_install_script.open_maldet_tarball_fd",
            _open_then_truncate,
        )
        with patch(
            "oyst_core.privileged.helper_install_script.subprocess.run",
        ) as run:
            rc = seal_and_run_install_tarball(str(tarball), digest)
        assert rc == 2
        run.assert_not_called()
    finally:
        shutil.rmtree(tarball.parent, ignore_errors=True)
