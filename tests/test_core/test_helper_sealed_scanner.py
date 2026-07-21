"""Tests for sealed runtime scanner helper."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged.helper_sealed_scanner import (
    seal_and_run_scanner,
    validate_sealed_source,
)


def _runtime_bin(tmp_path: Path, name: str) -> Path:
    home_shaped = (
        tmp_path / "home" / "u" / ".local" / "share" / "oysterav" / "runtime" / "x86_64" / "bin"
    )
    home_shaped.mkdir(parents=True)
    target = home_shaped / name
    target.write_bytes(b"#!/bin/sh\necho ok\n")
    return target


def test_validate_sealed_source_accepts_runtime_path(tmp_path: Path) -> None:
    target = _runtime_bin(tmp_path, "chkrootkit")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    validated = validate_sealed_source(str(target), "chkrootkit", digest)
    assert validated == target


def test_validate_sealed_source_rejects_hash_and_symlink(tmp_path: Path) -> None:
    target = _runtime_bin(tmp_path, "chkrootkit")
    with pytest.raises(ValueError, match="sha256"):
        validate_sealed_source(str(target), "chkrootkit", "deadbeef")
    link = target.parent / "chkrootkit-link"
    link.symlink_to(target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="symlink"):
        validate_sealed_source(str(link), "chkrootkit", digest)


def test_validate_sealed_source_rejects_outside_runtime(tmp_path: Path) -> None:
    outside = tmp_path / "chkrootkit"
    outside.write_bytes(b"x")
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="runtime"):
        validate_sealed_source(str(outside), "chkrootkit", digest)


def test_seal_and_run_scanner_rejects_bad_argv(tmp_path: Path) -> None:
    target = _runtime_bin(tmp_path, "chkrootkit")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="no arguments"):
        seal_and_run_scanner(str(target), "chkrootkit", digest, ["--evil"])


def test_seal_and_run_scanner_allows_chkrootkit_empty_argv(tmp_path: Path) -> None:
    target = _runtime_bin(tmp_path, "chkrootkit")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    seal_dir = tmp_path / "sealed"
    seal_dir.mkdir()
    with (
        patch("oyst_core.privileged.helper_sealed_scanner._SEAL_DIR", seal_dir),
        patch("oyst_core.privileged.helper_sealed_scanner.os.chown"),
        patch(
            "oyst_core.privileged.helper_sealed_scanner.subprocess.run",
            return_value=type("R", (), {"returncode": 0})(),
        ) as run,
    ):
        rc = seal_and_run_scanner(str(target), "chkrootkit", digest, [])
    assert rc == 0
    assert run.call_args[0][0][1:] == []
