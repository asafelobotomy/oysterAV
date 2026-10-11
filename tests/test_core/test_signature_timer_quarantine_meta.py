"""Full-mode signature freshness/timer (R3) and quarantine permission restore (R4)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core import signature_timer
from oyst_core.config import OysterConfig
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.privileged.runner import CommandResult
from oyst_core.quarantine import QuarantineVault
from oyst_core.quarantine_meta import restore_mode

# --- signature age -------------------------------------------------------------


def test_signature_age_uses_private_db_even_when_host_is_fresh(tmp_path: Path) -> None:
    runtime_db = tmp_path / "db"
    runtime_db.mkdir()
    daily = runtime_db / "daily.cld"
    daily.write_bytes(b"x")
    old = daily.stat().st_mtime - 10 * 24 * 3600
    os.utime(daily, (old, old))
    host = tmp_path / "host-daily.cvd"
    host.write_bytes(b"x")
    pack = FreshclamPack()
    with (
        patch("oyst_core.packs.freshclam.clamav_db_dir", return_value=runtime_db),
        patch("oyst_core.packs.freshclam.DAILY_CVD", [str(host)]),
        patch(
            "oyst_core.packs.freshclam.clamscan_database_args",
            return_value=[f"--database={runtime_db}"],
        ),
    ):
        age = pack.signature_age_hours()
        ages = pack.signature_ages()
    assert age is not None and age > 200
    assert ages["host"] is not None and ages["host"] < 1


def test_signature_age_uses_host_db_without_private_db(tmp_path: Path) -> None:
    host = tmp_path / "daily.cvd"
    host.write_bytes(b"x")
    with (
        patch("oyst_core.packs.freshclam.clamav_db_dir", return_value=tmp_path / "none"),
        patch("oyst_core.packs.freshclam.DAILY_CVD", [str(host)]),
        patch("oyst_core.packs.freshclam.clamscan_database_args", return_value=[]),
    ):
        age = FreshclamPack().signature_age_hours()
    assert age is not None and age < 1


# --- signature timer -------------------------------------------------------------


def _timer_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, mode: str, auto: bool
) -> list[list[str]]:
    cfg = OysterConfig()
    cfg.runtime.mode = mode  # type: ignore[assignment]
    cfg.runtime.auto_update_signatures = auto
    calls: list[list[str]] = []
    monkeypatch.setattr(signature_timer, "load_config", lambda: cfg)
    monkeypatch.setattr(signature_timer, "_user_systemd_dir", lambda: tmp_path)
    monkeypatch.setattr(signature_timer, "resolve_oyst_cli_path", lambda: "/usr/bin/oyst-cli")

    def fake_systemctl(args: list[str]) -> CommandResult:
        calls.append(args)
        return CommandResult(0, "", "")

    monkeypatch.setattr(signature_timer, "_run_user_systemctl", fake_systemctl)
    return calls


def test_timer_installed_and_enabled_in_full_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _timer_env(monkeypatch, tmp_path, mode="full", auto=True)
    result = signature_timer.apply_signature_timer()
    assert result["ok"] and result["enabled"]
    service = (tmp_path / signature_timer.UNIT_SERVICE).read_text(encoding="utf-8")
    timer = (tmp_path / signature_timer.UNIT_TIMER).read_text(encoding="utf-8")
    assert "ExecStart=/usr/bin/oyst-cli freshclam update --fangfrisch --json" in service
    assert "RandomizedDelaySec=30m" in timer and "Persistent=true" in timer
    assert ["enable", "--now", signature_timer.UNIT_TIMER] in calls


@pytest.mark.parametrize(("mode", "auto"), [("lite", True), ("full", False)])
def test_timer_removed_when_not_wanted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str, auto: bool
) -> None:
    calls = _timer_env(monkeypatch, tmp_path, mode=mode, auto=auto)
    (tmp_path / signature_timer.UNIT_TIMER).write_text("x", encoding="utf-8")
    (tmp_path / signature_timer.UNIT_SERVICE).write_text("x", encoding="utf-8")
    result = signature_timer.apply_signature_timer()
    assert result["ok"] and not result["enabled"]
    assert not (tmp_path / signature_timer.UNIT_TIMER).exists()
    assert ["disable", "--now", signature_timer.UNIT_TIMER] in calls


def test_services_freshclam_timer_full_mode_uses_user_timer() -> None:
    from oyst_core import services

    with (
        patch("oyst_core.runtime.manifest.is_full_mode", return_value=True),
        patch(
            "oyst_core.signature_timer.set_auto_update",
            return_value={"ok": True, "message": "on"},
        ) as set_mock,
        patch.object(services, "_systemctl_set") as distro_mock,
    ):
        result = services.set_service("freshclam-timer", "on")
    set_mock.assert_called_once_with(True)
    distro_mock.assert_not_called()
    assert result["ok"] and result["unit"] == signature_timer.UNIT_TIMER


# --- quarantine permission restore --------------------------------------------------


def _vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QuarantineVault:
    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    return QuarantineVault(vault_dir)


@pytest.mark.parametrize(
    ("original", "restored"),
    [(0o755, 0o755), (0o4755, 0o755), (0o666, 0o644), (0o444, 0o644), (0o600, 0o600)],
)
def test_restore_keeps_masked_original_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, original: int, restored: int
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "script.sh"
    sample.write_bytes(b"#!/bin/sh\n")
    os.chmod(sample, original)
    mtime = 1_700_000_000.0
    os.utime(sample, (mtime, mtime))
    entry = vault.add(str(sample), "Test")
    with vault._connect() as conn:
        meta = json.loads(
            conn.execute("SELECT metadata FROM entries WHERE id = ?", (entry.id,)).fetchone()[0]
        )
    assert meta["mode"] == stat.S_IMODE(original)
    dest = vault.restore(entry.id)
    assert stat.S_IMODE(dest.stat().st_mode) == restored
    assert dest.stat().st_mtime == pytest.approx(mtime)


def test_legacy_entry_restores_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault(tmp_path, monkeypatch)
    sample = tmp_path / "old.bin"
    sample.write_bytes(b"x")
    os.chmod(sample, 0o755)
    entry = vault.add(str(sample), "Test")
    with vault._connect() as conn:
        conn.execute("UPDATE entries SET metadata = ? WHERE id = ?", ("{}", entry.id))
        conn.commit()
    dest = vault.restore(entry.id)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@pytest.mark.parametrize("bad", [None, True, -1, 0o17777, "0755", 1.5])
def test_tampered_mode_metadata_falls_back_to_0600(bad: object) -> None:
    assert restore_mode({"mode": bad}) == 0o600
