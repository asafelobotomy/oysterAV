"""Tests for short-lived doctor_all cache."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from oyst_core import doctor_cache


def test_doctor_all_caches_within_ttl(monkeypatch: object) -> None:
    doctor_cache.invalidate_doctor_cache()
    calls = {"n": 0}

    class FakePack:
        name = "fake"

        def doctor(self) -> MagicMock:
            calls["n"] += 1
            status = MagicMock()
            status.model_dump.return_value = {"name": "fake", "installed": True}
            return status

    with patch("oyst_core.doctor_cache.get_registry") as reg:
        reg.return_value.all.return_value = [FakePack()]
        first = doctor_cache.doctor_all(ttl_sec=60.0)
        second = doctor_cache.doctor_all(ttl_sec=60.0)
    assert first == second == [{"name": "fake", "installed": True}]
    assert calls["n"] == 1


def test_doctor_all_force_and_invalidate() -> None:
    doctor_cache.invalidate_doctor_cache()
    calls = {"n": 0}

    class FakePack:
        def doctor(self) -> MagicMock:
            calls["n"] += 1
            status = MagicMock()
            status.model_dump.return_value = {"name": "x", "n": calls["n"]}
            return status

    with patch("oyst_core.doctor_cache.get_registry") as reg:
        reg.return_value.all.return_value = [FakePack()]
        doctor_cache.doctor_all(ttl_sec=60.0)
        doctor_cache.invalidate_doctor_cache()
        doctor_cache.doctor_all(ttl_sec=60.0, force=True)
    assert calls["n"] == 2
