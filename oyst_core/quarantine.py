"""Quarantine vault with SHA-256 verification."""

from __future__ import annotations

import hashlib
import json
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
        src = Path(source).expanduser()
        if src.is_symlink():
            raise ValueError("refuse to quarantine through symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            src_fd = os.open(str(src), flags)
        except FileNotFoundError as exc:
            raise FileNotFoundError(source) from exc
        except OSError as exc:
            raise ValueError(f"cannot open quarantine source: {exc}") from exc
        dest: Path | None = None
        entry_id = 0
        try:
            st = os.fstat(src_fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("quarantine add requires a regular file")
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(src_fd, 65536)
                if not chunk:
                    break
                hasher.update(chunk)
            sha = hasher.hexdigest()
            os.lseek(src_fd, 0, os.SEEK_SET)
            resolved = src.resolve(strict=False)
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            dest = self.vault_dir / f"{ts}_{uuid.uuid4().hex[:8]}_{resolved.name}"
            if dest.exists():
                raise RuntimeError(f"quarantine destination collision: {dest}")
            with open(dest, "wb") as out_f:
                while True:
                    chunk = os.read(src_fd, 65536)
                    if not chunk:
                        break
                    out_f.write(chunk)
                out_f.flush()
                os.fsync(out_f.fileno())
            dir_fd = os.open(str(self.vault_dir), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
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
                        str(resolved),
                        str(dest),
                        sha,
                        threat_name,
                        datetime.now().isoformat(),
                        json.dumps({}),
                    ),
                )
                entry_id = int(cur.lastrowid or 0)
                if entry_id == 0:
                    raise RuntimeError("failed to insert quarantine entry")
                conn.commit()
            resolved.unlink()
            src = resolved
        except Exception:
            if dest is not None and dest.exists():
                dest.unlink(missing_ok=True)
            raise
        finally:
            try:
                os.close(src_fd)
            except OSError:
                pass
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
        current = self._sha256(vault)
        if current != entry.sha256:
            raise ValueError("vault file hash mismatch — possible tampering")
        dest = Path(entry.original_path).expanduser()
        if dest.is_symlink():
            raise ValueError("refuse restore through symlink")
        dest_resolved = dest.expanduser()
        # Do not follow dest symlink: create with O_EXCL|O_NOFOLLOW then copy.
        parent = dest_resolved.parent
        parent.mkdir(parents=True, exist_ok=True)
        if parent.stat().st_uid != os.getuid():
            raise ValueError("restore parent directory not owned by current user")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            dest_fd = os.open(str(dest_resolved), flags, 0o600)
        except FileExistsError as exc:
            raise ValueError(f"refuse overwrite of existing path: {dest_resolved}") from exc
        try:
            with open(vault, "rb") as src_f:
                while True:
                    chunk = src_f.read(65536)
                    if not chunk:
                        break
                    os.write(dest_fd, chunk)
        finally:
            os.close(dest_fd)
        vault.unlink()
        with self._connect() as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        SecurityAudit().log(
            "quarantine.restore",
            str(entry_id),
            success=True,
            data={"dest": str(dest_resolved.resolve())},
        )
        return dest_resolved.resolve()

    def delete(self, entry_id: int) -> None:
        entry = self.get(entry_id)
        if not entry:
            raise KeyError(entry_id)
        vault = self._contained_vault_path(entry.vault_path)
        if vault.exists():
            vault.unlink()
        with self._connect() as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        SecurityAudit().log("quarantine.delete", str(entry_id), success=True)

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
