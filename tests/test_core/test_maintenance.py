"""Maintenance bootstrap / post-update unit tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core.maintenance import run_bootstrap, run_post_update
from oyst_core.models import PackStatus, PackTier


def _pack(name: str, *, installed: bool = True) -> MagicMock:
    pack = MagicMock()
    pack.name = name
    pack.tier = PackTier.REQUIRED
    pack.doctor.return_value = PackStatus(
        name=name,
        tier=PackTier.REQUIRED,
        installed=installed,
    )
    return pack


def test_run_bootstrap_skips_missing_and_aggregates(tmp_path) -> None:  # type: ignore[no-untyped-def]
    registry = MagicMock()
    registry.all.return_value = [_pack("clamav"), _pack("freshclam", installed=False)]

    fresh = MagicMock()
    fresh.doctor.return_value = PackStatus(
        name="freshclam", tier=PackTier.REQUIRED, installed=False
    )
    fang = MagicMock()
    fang.doctor.return_value = PackStatus(
        name="fangfrisch", tier=PackTier.OPTIONAL, installed=False
    )
    rkh = MagicMock()
    rkh.doctor.return_value = PackStatus(name="rkhunter", tier=PackTier.RECOMMENDED, installed=True)
    rkh.propupd.return_value = (True, "ok")
    lynis = MagicMock()
    lynis.doctor.return_value = PackStatus(name="lynis", tier=PackTier.RECOMMENDED, installed=True)
    lynis.audit.return_value = (True, "report", 80)

    with (
        patch("oyst_core.maintenance.get_registry", return_value=registry),
        patch("oyst_core.maintenance.FreshclamPack", return_value=fresh),
        patch("oyst_core.maintenance.FangfrischPack", return_value=fang),
        patch("oyst_core.maintenance.RKHunterPack", return_value=rkh),
        patch("oyst_core.maintenance.LynisPack", return_value=lynis),
        patch("oyst_core.maintenance.EventLog") as events_cls,
    ):
        events_cls.return_value.log = MagicMock()
        steps = run_bootstrap(skip_lynis=False)

    names = [s["step"] for s in steps]
    assert "doctor-clamav" in names
    assert any(s["step"] == "freshclam" and s.get("skipped") for s in steps)
    assert any(s["step"] == "fangfrisch" and s.get("skipped") for s in steps)
    assert any(s["step"] == "rkhunter-propupd" and s["ok"] for s in steps)
    assert any(s["step"] == "lynis" and s.get("hardening_index") == 80 for s in steps)


def test_run_bootstrap_skip_lynis() -> None:
    registry = MagicMock()
    registry.all.return_value = []
    fresh = MagicMock()
    fresh.doctor.return_value = PackStatus(
        name="freshclam", tier=PackTier.REQUIRED, installed=False
    )
    fang = MagicMock()
    fang.doctor.return_value = PackStatus(
        name="fangfrisch", tier=PackTier.OPTIONAL, installed=False
    )
    rkh = MagicMock()
    rkh.doctor.return_value = PackStatus(
        name="rkhunter", tier=PackTier.RECOMMENDED, installed=False
    )

    with (
        patch("oyst_core.maintenance.get_registry", return_value=registry),
        patch("oyst_core.maintenance.FreshclamPack", return_value=fresh),
        patch("oyst_core.maintenance.FangfrischPack", return_value=fang),
        patch("oyst_core.maintenance.RKHunterPack", return_value=rkh),
        patch("oyst_core.maintenance.EventLog") as events_cls,
    ):
        events_cls.return_value.log = MagicMock()
        steps = run_bootstrap(skip_lynis=True)

    assert all(s["step"] != "lynis" for s in steps)


def test_run_post_update_installed_packs() -> None:
    fresh = MagicMock()
    fresh.doctor.return_value = PackStatus(name="freshclam", tier=PackTier.REQUIRED, installed=True)
    fresh.update.return_value = (True, "updated")
    fang = MagicMock()
    fang.doctor.return_value = PackStatus(name="fangfrisch", tier=PackTier.OPTIONAL, installed=True)
    fang.refresh.return_value = (True, "refreshed")
    rkh = MagicMock()
    rkh.doctor.return_value = PackStatus(name="rkhunter", tier=PackTier.RECOMMENDED, installed=True)
    rkh.propupd.return_value = (True, "propupd")

    with (
        patch("oyst_core.maintenance.FreshclamPack", return_value=fresh),
        patch("oyst_core.maintenance.FangfrischPack", return_value=fang),
        patch("oyst_core.maintenance.RKHunterPack", return_value=rkh),
        patch("oyst_core.maintenance.EventLog") as events_cls,
    ):
        events_cls.return_value.log = MagicMock()
        steps = run_post_update()

    assert {s["step"] for s in steps} == {"freshclam", "fangfrisch", "rkhunter-propupd"}
    assert all(s["ok"] for s in steps)
