"""Quarantine vault with SHA-256 verification."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
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
        try:
            self.vault_dir.chmod(0o700)
        except OSError:
            pass
        self.db_path = self.vault_dir / "vault.db"
        self._init_db()
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

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
        src = Path(source).expanduser().resolve()
        if not src.exists():
            raise FileNotFoundError(source)
        digest = self._sha256(src)
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        dest_name = f"{ts}_{src.name}"
        dest = self.vault_dir / dest_name
        shutil.move(str(src), str(dest))
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
                    str(src),
                    str(dest),
                    digest,
                    threat_name,
                    datetime.now().isoformat(),
                    json.dumps({}),
                ),
            )
            entry_id = int(cur.lastrowid or 0)
            if entry_id == 0:
                raise RuntimeError("failed to insert quarantine entry")
        return QuarantineEntry(
            id=entry_id,
            original_path=str(src),
            vault_path=str(dest),
            sha256=digest,
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
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(vault), str(dest))
        with self._connect() as conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        SecurityAudit().log(
            "quarantine.restore",
            str(entry_id),
            success=True,
            data={"dest": str(dest)},
        )
        return dest

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
