"""Quarantine vault mutation and path-safety tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from oyst_core.config import OysterConfig
from oyst_core.quarantine import QuarantineVault


def _vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QuarantineVault:
    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    return QuarantineVault(vault_dir)


def test_quarantine_delete_removes_file_and_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "malware.bin"
    sample.write_bytes(b"evil")
    entry = vault.add(str(sample), "Eicar")
    vault_file = Path(entry.vault_path)
    assert vault_file.exists()

    vault.delete(entry.id)
    assert not vault_file.exists()
    assert vault.get(entry.id) is None
    assert entry.id not in {e.id for e in vault.list_entries()}


def test_quarantine_delete_missing_id_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    with pytest.raises(KeyError):
        vault.delete(99999)


def test_quarantine_path_escape_rejected_on_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    with vault._connect() as conn:
        conn.execute(
            """
            INSERT INTO entries (
                original_path, vault_path, sha256, threat_name, quarantined_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(tmp_path / "orig"),
                str(outside),
                "0" * 64,
                "escape",
                "2026-01-01T00:00:00",
                "{}",
            ),
        )
        entry_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    with pytest.raises(ValueError, match="escapes vault"):
        vault.restore(entry_id)


def test_quarantine_path_escape_rejected_on_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    outside = tmp_path / "outside2.bin"
    outside.write_bytes(b"y")
    with vault._connect() as conn:
        conn.execute(
            """
            INSERT INTO entries (
                original_path, vault_path, sha256, threat_name, quarantined_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(tmp_path / "orig2"),
                str(outside),
                "0" * 64,
                "escape",
                "2026-01-01T00:00:00",
                "{}",
            ),
        )
        entry_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    with pytest.raises(ValueError, match="escapes vault"):
        vault.delete(entry_id)
    assert outside.exists()


def test_quarantine_verify_detects_corrupt_and_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "good.txt"
    sample.write_text("ok\n", encoding="utf-8")
    entry = vault.add(str(sample), "t")

    # Tamper vault file
    Path(entry.vault_path).write_text("tampered\n", encoding="utf-8")

    # Escape entry
    outside = tmp_path / "escaped.bin"
    outside.write_bytes(b"z")
    with vault._connect() as conn:
        conn.execute(
            """
            INSERT INTO entries (
                original_path, vault_path, sha256, threat_name, quarantined_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(tmp_path / "orig3"),
                str(outside),
                "ab" * 32,
                "escape",
                "2026-01-01T00:00:00",
                "{}",
            ),
        )
        escape_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    # Missing file entry
    with vault._connect() as conn:
        conn.execute(
            """
            INSERT INTO entries (
                original_path, vault_path, sha256, threat_name, quarantined_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(tmp_path / "orig4"),
                str(vault.vault_dir / "missing.bin"),
                "cd" * 32,
                "gone",
                "2026-01-01T00:00:00",
                "{}",
            ),
        )
        missing_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    bad = vault.verify()
    assert entry.id in bad
    assert escape_id in bad
    assert missing_id in bad


def test_contained_vault_path_allows_nested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    nested = vault.vault_dir / "sub" / "file.bin"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"1")
    assert vault._contained_vault_path(nested) == nested.resolve()


def test_quarantine_add_rejects_symlink_and_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    target = tmp_path / "real.bin"
    target.write_bytes(b"x")
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        vault.add(str(link), "t")
    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        vault.add(str(directory), "t")


def test_quarantine_restore_refuses_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload")
    entry = vault.add(str(sample), "t")
    # Recreate original path so restore hits O_EXCL
    sample.write_bytes(b"occupied")
    with pytest.raises(ValueError, match="overwrite"):
        vault.restore(entry.id)


def test_quarantine_add_atomic_leaves_db_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"payload-bytes")
    entry = vault.add(str(sample), "Threat")
    assert not sample.exists()
    assert Path(entry.vault_path).is_file()
    assert vault.get(entry.id) is not None


def test_quarantine_list_and_reconcile_orphans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    orphan = vault.vault_dir / "20260101120000_abcd1234_clamdscan"
    orphan.write_bytes(b"orphan")
    listed = vault.list_orphans()
    assert str(orphan.resolve()) in listed
    result = vault.reconcile_orphans(delete=True)
    assert str(orphan.resolve()) in result["deleted"]
    assert not orphan.exists()
    assert vault.list_orphans() == []


def test_quarantine_refuse_scanner_basename() -> None:
    from oyst_core.quarantine_guards import quarantine_refuse_reason

    assert quarantine_refuse_reason("/usr/bin/clamdscan") is not None
    assert quarantine_refuse_reason("/tmp/eicar.com") is None


def test_vault_add_refuses_scanner_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    runtime = tmp_path / "runtime"
    (runtime / "bin").mkdir(parents=True)
    monkeypatch.setattr("oyst_core.quarantine_guards.runtime_root", lambda: runtime)
    monkeypatch.setattr("oyst_core.quarantine_guards.runtime_bin_dir", lambda: runtime / "bin")
    scanner = runtime / "bin" / "clamscan"
    scanner.write_bytes(b"fake")
    with pytest.raises(ValueError, match="refusing"):
        vault.add(str(scanner), "Eicar")
    # Same basename outside real install/runtime dirs is a normal detection.
    decoy = tmp_path / "Downloads" / "clamscan"
    decoy.parent.mkdir()
    decoy.write_bytes(b"fake")
    from oyst_core.quarantine_guards import quarantine_refuse_reason

    assert quarantine_refuse_reason(str(decoy)) is None


def test_quarantine_add_parent_swap_never_deletes_victim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit S4: swapping a parent dir for a symlink mid-copy must not hit the victim."""
    from oyst_core import quarantine as q_mod

    vault = _vault(tmp_path, monkeypatch)
    attacker = tmp_path / "attacker"
    (attacker / "d").mkdir(parents=True)
    (attacker / "d" / ".bashrc").write_bytes(b"X5O!P%@AP eicar-ish")
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / ".bashrc").write_bytes(b"victim config")

    real_write_all = q_mod._write_all
    swapped = False

    def _swap_then_write(fd: int, data: bytes) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            (attacker / "d").rename(attacker / "d-old")
            (attacker / "d").symlink_to(victim)
        real_write_all(fd, data)

    monkeypatch.setattr(q_mod, "_write_all", _swap_then_write)
    entry = vault.add(str(attacker / "d" / ".bashrc"), "Eicar")
    assert (victim / ".bashrc").read_bytes() == b"victim config"
    assert not (attacker / "d-old" / ".bashrc").exists()
    assert entry.original_path == str(attacker / "d-old" / ".bashrc")
    assert Path(entry.vault_path).read_bytes() == b"X5O!P%@AP eicar-ish"


def test_open_dir_nofollow_refuses_symlink_component(tmp_path: Path) -> None:
    from oyst_core.quarantine import _open_dir_nofollow

    real = tmp_path / "real" / "sub"
    real.mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    os.close(_open_dir_nofollow(real))
    with pytest.raises(OSError):
        _open_dir_nofollow(tmp_path / "link" / "sub")


def test_quarantine_add_long_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / ("a" * 250)
    sample.write_bytes(b"evil")
    entry = vault.add(str(sample), "Eicar")
    assert not sample.exists()
    assert entry.original_path == str(sample)
    assert Path(entry.vault_path).read_bytes() == b"evil"
