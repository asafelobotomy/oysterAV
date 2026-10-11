"""Quarantine vault with SHA-256 verification."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import sqlite3
import stat
import uuid
from datetime import datetime
from pathlib import Path

from oyst_core.audit import SecurityAudit
from oyst_core.config import load_config
from oyst_core.models import QuarantineEntry
from oyst_core.quarantine_meta import apply_restored_metadata, capture_metadata, read_metadata


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _open_dir_nofollow(path: Path) -> int:
    """Open an absolute directory walking each component with O_NOFOLLOW.

    Fails (ELOOP/ENOTDIR) if any component is, or is swapped for, a symlink.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
    except BaseException:
        os.close(fd)
        raise
    return fd


def _fd_dir_path(dir_fd: int, fallback: Path) -> Path:
    """Real path of an open directory fd (what was actually opened), else fallback."""
    try:
        return Path(os.readlink(f"/proc/self/fd/{dir_fd}"))
    except OSError:
        return fallback


class QuarantineVault:
    def __init__(self, vault_dir: Path | None = None) -> None:
        cfg = load_config()
        self.vault_dir = (vault_dir or cfg.vault_path()).expanduser().resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir.chmod(0o700)
        mode = self.vault_dir.stat().st_mode & 0o777
        if mode != 0o700:
            raise RuntimeError(f"quarantine vault must be mode 0700 (got {oct(mode)})")
        self.db_path = self.vault_dir / "vault.db"
        self._init_db()
        self.db_path.chmod(0o600)
        db_mode = self.db_path.stat().st_mode & 0o777
        if db_mode != 0o600:
            raise RuntimeError(f"vault.db must be mode 0600 (got {oct(db_mode)})")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _contained_vault_path(self, vault_path: str | Path) -> Path:
        path = Path(vault_path).expanduser().resolve()
        try:
            path.relative_to(self.vault_dir)
        except ValueError as exc:
            raise ValueError(f"quarantine path escapes vault: {path}") from exc
        return path

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    vault_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    threat_name TEXT,
                    quarantined_at TEXT NOT NULL,
                    metadata TEXT
                )
                """
            )

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def add(self, source: str, threat_name: str = "") -> QuarantineEntry:
        from oyst_core.quarantine_guards import quarantine_refuse_reason

        refuse = quarantine_refuse_reason(source)
        if refuse:
            SecurityAudit().log(
                "quarantine.refuse",
                source,
                success=False,
                data={"reason": refuse, "threat": threat_name},
            )
            raise ValueError(refuse)
        src = Path(source).expanduser()
        if src.is_symlink():
            raise ValueError("refuse to quarantine through symlink")
        try:
            resolved = src.resolve(strict=True)
        except FileNotFoundError as exc:
            raise FileNotFoundError(source) from exc
        except OSError as exc:
            raise ValueError(f"cannot resolve quarantine source: {exc}") from exc
        # Work relative to a parent directory fd and verify the inode before
        # unlinking, so a parent swapped for a symlink mid-copy can never make us
        # delete a different file than the one copied into the vault (TOCTOU).
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            parent_fd = _open_dir_nofollow(resolved.parent)
        except OSError as exc:
            raise ValueError(f"cannot open quarantine source directory: {exc}") from exc
        name = resolved.name
        dest: Path | None = None
        entry_id = 0
        src_fd = -1
        try:
            try:
                src_fd = os.open(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise FileNotFoundError(source) from exc
            except OSError as exc:
                raise ValueError(f"cannot open quarantine source: {exc}") from exc
            st = os.fstat(src_fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("quarantine add requires a regular file")
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            # Original name lives in the DB only; long names would exceed NAME_MAX.
            dest = self.vault_dir / f"{ts}_{uuid.uuid4().hex}.bin"
            out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow
            out_fd = os.open(str(dest), out_flags, 0o600)
            hasher = hashlib.sha256()
            try:
                os.fchmod(out_fd, 0o600)
                while True:
                    chunk = os.read(src_fd, 65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    _write_all(out_fd, chunk)
                os.fsync(out_fd)
            finally:
                os.close(out_fd)
            sha = hasher.hexdigest()
            vault_dir_fd = os.open(str(self.vault_dir), os.O_RDONLY)
            try:
                os.fsync(vault_dir_fd)
            finally:
                os.close(vault_dir_fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino):
                raise ValueError("quarantine source changed during copy; refusing to unlink")
            original = _fd_dir_path(parent_fd, resolved.parent) / name
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO entries (
                        original_path, vault_path, sha256,
                        threat_name, quarantined_at, metadata
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(original),
                        str(dest),
                        sha,
                        threat_name,
                        datetime.now().isoformat(),
                        capture_metadata(st),
                    ),
                )
                entry_id = int(cur.lastrowid or 0)
                if entry_id == 0:
                    raise RuntimeError("failed to insert quarantine entry")
                conn.commit()
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                with self._connect() as conn:
                    conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
                    conn.commit()
                raise
            src = original
        except Exception:
            if dest is not None and dest.exists():
                dest.unlink(missing_ok=True)
            raise
        finally:
            for fd in (src_fd, parent_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
        return QuarantineEntry(
            id=entry_id,
            original_path=str(src),
            vault_path=str(dest),
            sha256=sha,
            threat_name=threat_name,
            quarantined_at=datetime.now(),
        )

    def list_entries(self) -> list[QuarantineEntry]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM entries ORDER BY id DESC").fetchall()
        return [
            QuarantineEntry(
                id=int(r["id"]),
                original_path=str(r["original_path"]),
                vault_path=str(r["vault_path"]),
                sha256=str(r["sha256"]),
                threat_name=str(r["threat_name"] or ""),
                quarantined_at=datetime.fromisoformat(str(r["quarantined_at"])),
            )
            for r in rows
        ]

    def get(self, entry_id: int) -> QuarantineEntry | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        return QuarantineEntry(
            id=int(row["id"]),
            original_path=str(row["original_path"]),
            vault_path=str(row["vault_path"]),
            sha256=str(row["sha256"]),
            threat_name=str(row["threat_name"] or ""),
            quarantined_at=datetime.fromisoformat(str(row["quarantined_at"])),
        )

    def restore(self, entry_id: int) -> Path:
        entry = self.get(entry_id)
        if not entry:
            raise KeyError(entry_id)
        vault = self._contained_vault_path(entry.vault_path)
        if not vault.exists():
            raise FileNotFoundError(entry.vault_path)
        if self._sha256(vault) != entry.sha256:
            raise ValueError("vault file hash mismatch — possible tampering")
        with self._connect() as conn:
            meta = read_metadata(conn, entry_id)
        dest = Path(entry.original_path).expanduser()
        if not dest.is_absolute() or dest.name in ("", ".", ".."):
            raise ValueError(f"invalid restore destination: {dest}")
        # Nofollow walk of every ancestor; never mkdir from DB-sourced paths.
        try:
            parent_fd = _open_dir_nofollow(dest.parent)
        except FileNotFoundError as exc:
            raise ValueError(f"restore parent directory missing: {dest.parent}") from exc
        except OSError as exc:
            raise ValueError(f"refuse restore through symlink or bad parent: {exc}") from exc
        name = dest.name
        try:
            if os.fstat(parent_fd).st_uid != os.getuid():
                raise ValueError("restore parent directory not owned by current user")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                dest_fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise ValueError(f"refuse overwrite of existing path: {dest}") from exc
            try:
                with open(vault, "rb") as src_f:
                    for chunk in iter(lambda: src_f.read(65536), b""):
                        _write_all(dest_fd, chunk)
                apply_restored_metadata(dest_fd, meta)
                os.fsync(dest_fd)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(name, dir_fd=parent_fd)
                raise
            finally:
                os.close(dest_fd)
            os.fsync(parent_fd)
            restored = _fd_dir_path(parent_fd, dest.parent) / name
        finally:
            os.close(parent_fd)
        vault.unlink()
        with self._connect() as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        audit_data = {"dest": str(restored)}
        SecurityAudit().log("quarantine.restore", str(entry_id), success=True, data=audit_data)
        return restored

    def delete(self, entry_id: int) -> None:
        entry = self.get(entry_id)
        if not entry:
            raise KeyError(entry_id)
        vault = self._contained_vault_path(entry.vault_path)
        if vault.exists():
            if load_config().quarantine.secure_wipe:
                self._secure_wipe(vault)
            vault.unlink(missing_ok=True)
        with self._connect() as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        SecurityAudit().log("quarantine.delete", str(entry_id), success=True)

    @staticmethod
    def _secure_wipe(path: Path) -> None:
        """Best-effort single-pass overwrite before unlink (not a formal sanitize)."""
        try:
            size = path.stat().st_size
        except OSError:
            return
        try:
            with path.open("r+b", buffering=0) as handle:
                remaining = size
                chunk = b"\0" * min(65536, max(size, 1))
                while remaining > 0:
                    written = handle.write(chunk if remaining >= len(chunk) else b"\0" * remaining)
                    if written <= 0:
                        break
                    remaining -= written
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            return

    def verify(self) -> list[int]:
        bad: list[int] = []
        for entry in self.list_entries():
            try:
                vault = self._contained_vault_path(entry.vault_path)
            except ValueError:
                bad.append(entry.id)
                continue
            if not vault.exists():
                bad.append(entry.id)
                continue
            if self._sha256(vault) != entry.sha256:
                bad.append(entry.id)
        return bad

    _ORPHAN_NAME_RE = re.compile(r"^\d{14}_[0-9a-f]{8}_")

    def list_orphans(self) -> list[str]:
        """Vault files matching quarantine naming with no DB row."""
        tracked = {str(Path(e.vault_path).resolve()) for e in self.list_entries()}
        orphans: list[str] = []
        for path in self.vault_dir.iterdir():
            if not path.is_file() or path.name == "vault.db":
                continue
            if not self._ORPHAN_NAME_RE.match(path.name):
                continue
            try:
                resolved = str(path.resolve())
            except OSError:
                continue
            if resolved not in tracked:
                orphans.append(resolved)
        return sorted(orphans)

    def reconcile_orphans(self, *, delete: bool = False) -> dict[str, object]:
        orphans = self.list_orphans()
        deleted: list[str] = []
        if delete:
            for path_str in orphans:
                path = Path(path_str)
                try:
                    contained = self._contained_vault_path(path)
                    if contained.is_file():
                        contained.unlink()
                        deleted.append(str(contained))
                except (OSError, ValueError):
                    continue
            if deleted:
                SecurityAudit().log(
                    "quarantine.reconcile",
                    "delete-orphans",
                    success=True,
                    data={"count": len(deleted)},
                )
        return {
            "orphans": orphans,
            "deleted": deleted,
            "ok": True,
        }
