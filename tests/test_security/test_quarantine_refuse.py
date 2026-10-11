"""Adversarial quarantine refuse-guard coverage (F-01)."""

from __future__ import annotations

from pathlib import Path

import pytest

from oyst_core.config import OysterConfig
from oyst_core.quarantine import QuarantineVault
from oyst_core.virusevent import handle_virusevent

pytestmark = pytest.mark.security


def _vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> QuarantineVault:
    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    return QuarantineVault(vault_dir)


@pytest.mark.parametrize(
    "name",
    ["clamscan", "rkhunter", "oyst-cli", "maldet"],
)
def test_vault_add_refuses_scanner_in_runtime_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    runtime = _runtime(tmp_path, monkeypatch)
    target = runtime / "bin" / name
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="refusing"):
        vault.add(str(target), "threat")


@pytest.mark.parametrize("name", ["clamscan", "rkhunter", "oyst-cli", "maldet"])
def test_scanner_basename_outside_install_dirs_is_quarantinable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    from oyst_core.quarantine_guards import quarantine_refuse_reason

    _runtime(tmp_path, monkeypatch)
    target = tmp_path / "Downloads" / name
    target.parent.mkdir()
    target.write_bytes(b"x")
    assert quarantine_refuse_reason(str(target)) is None


def _runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    runtime = tmp_path / "runtime"
    (runtime / "bin").mkdir(parents=True)
    monkeypatch.setattr("oyst_core.quarantine_guards.runtime_root", lambda: runtime)
    monkeypatch.setattr("oyst_core.quarantine_guards.runtime_bin_dir", lambda: runtime / "bin")
    return runtime


def test_virusevent_handle_surfaces_refuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    cfg.quarantine.auto = True
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    monkeypatch.setattr("oyst_core.virusevent.load_config", lambda: cfg)

    scanner = _runtime(tmp_path, monkeypatch) / "bin" / "clamdscan"
    scanner.write_bytes(b"x")
    with (
        patch("oyst_core.virusevent.EventLog"),
        patch("oyst_core.virusevent.SecurityAudit"),
        patch("oyst_core.virusevent._notify"),
    ):
        result = handle_virusevent(
            env={
                "CLAM_VIRUSEVENT_FILENAME": str(scanner),
                "CLAM_VIRUSEVENT_VIRUSNAME": "Eicar-Test-Signature",
            },
            quarantine=True,
        )
    assert result["ok"] is True
    assert result["quarantined"] is False
    assert result.get("quarantine_error")
    assert "refusing" in str(result["quarantine_error"])
