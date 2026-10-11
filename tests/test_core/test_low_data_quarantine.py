"""Low-severity quarantine restore hardening regressions."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from oyst_core import quarantine as q_mod
from oyst_core.config import OysterConfig
from oyst_core.quarantine import QuarantineVault


def _vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QuarantineVault:
    from oyst_core import config as cfg_mod

    monkeypatch.setenv("HOME", str(tmp_path))
    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    return QuarantineVault(vault_dir)


def _quarantined(vault: QuarantineVault, tmp_path: Path) -> tuple[Path, int]:
    work = tmp_path / "work"
    work.mkdir()
    sample = work / "sample.bin"
    sample.write_bytes(b"payload" * 1000)
    return sample, vault.add(str(sample), "t").id


def test_restore_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample, entry_id = _quarantined(vault, tmp_path)
    restored = vault.restore(entry_id)
    assert restored == sample
    assert sample.read_bytes() == b"payload" * 1000
    assert sample.stat().st_mode & 0o777 == 0o600
    assert vault.get(entry_id) is None


def test_restore_refuses_symlinked_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample, entry_id = _quarantined(vault, tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    shutil.rmtree(sample.parent)
    sample.parent.symlink_to(elsewhere)
    with pytest.raises(ValueError, match="symlink"):
        vault.restore(entry_id)
    assert list(elsewhere.iterdir()) == []
    assert vault.get(entry_id) is not None


def test_restore_refuses_missing_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample, entry_id = _quarantined(vault, tmp_path)
    shutil.rmtree(sample.parent)
    with pytest.raises(ValueError, match="parent directory missing"):
        vault.restore(entry_id)
    assert not sample.parent.exists()
    assert vault.get(entry_id) is not None


def test_restore_write_error_removes_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample, entry_id = _quarantined(vault, tmp_path)

    def boom(fd: int, data: bytes) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(q_mod, "_write_all", boom)
    with pytest.raises(OSError):
        vault.restore(entry_id)
    assert not sample.exists()
    entry = vault.get(entry_id)
    assert entry is not None and Path(entry.vault_path).exists()
    monkeypatch.undo()
    # Retry is not blocked by a leftover partial ("refuse overwrite").
    vault = _vault(tmp_path, monkeypatch)
    assert vault.restore(entry_id) == sample


def test_write_all_handles_short_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    written: list[bytes] = []

    def short_write(fd: int, data: memoryview) -> int:
        chunk = bytes(data[:3])
        written.append(chunk)
        return len(chunk)

    monkeypatch.setattr(q_mod.os, "write", short_write)
    q_mod._write_all(0, b"abcdefgh")
    assert b"".join(written) == b"abcdefgh"
