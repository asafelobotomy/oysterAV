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
def test_vault_add_refuses_denylisted_basenames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    vault = _vault(tmp_path, monkeypatch)
    target = tmp_path / name
    target.write_bytes(b"x")
    with pytest.raises(ValueError, match="refusing"):
        vault.add(str(target), "threat")


def test_virusevent_handle_surfaces_refuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import patch

    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    cfg.quarantine.auto = True
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)
    monkeypatch.setattr("oyst_core.virusevent.load_config", lambda: cfg)

    scanner = tmp_path / "clamdscan"
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
