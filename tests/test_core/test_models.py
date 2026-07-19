"""Core library tests."""

from __future__ import annotations

from pathlib import Path

from oyst_core.config import OysterConfig, load_config, save_config
from oyst_core.models import PROFILE_PACKS, ScanProfile
from oyst_core.orchestrator import JobOrchestrator
from oyst_core.quarantine import QuarantineVault
from oyst_core.registry import get_registry
from oyst_core.rpc_auth import ensure_rpc_token
from oyst_core.serve import SCHEMA_VERSION, RpcServer


def _rpc_request(
    server: RpcServer,
    method: str,
    params: dict | None = None,
    *,
    req_id: int = 1,
) -> dict:
    token = ensure_rpc_token()
    return server.handle(
        {"method": method, "params": params or {}, "id": req_id, "auth": token},
    )


def test_profile_packs() -> None:
    from oyst_core.models import AUDIT_ONLY_PACKS, PROFILE_AUDIT_PACKS

    assert "clamav" in PROFILE_PACKS[ScanProfile.QUICK]
    assert "rkhunter" in PROFILE_PACKS[ScanProfile.INTEGRITY]
    assert "lynis" not in PROFILE_PACKS[ScanProfile.SUITE]
    assert "lynis" in PROFILE_AUDIT_PACKS[ScanProfile.SUITE]
    assert "lynis" in AUDIT_ONLY_PACKS


def test_custom_packs_split_lynis_to_audit() -> None:
    orch = JobOrchestrator()
    path_names, audit_names = orch._split_path_and_audit_packs(
        ScanProfile.CUSTOM,
        ["clamav", "lynis", "rkhunter"],
    )
    assert path_names == ["clamav", "rkhunter"]
    assert audit_names == ["lynis"]


def test_registry_has_packs() -> None:
    reg = get_registry()
    names = reg.names()
    assert "clamav" in names
    assert "lynis" in names
    assert "maldet" in names
    assert "fail2ban" in names
    assert "fangfrisch" in names


def test_runtime_checksums_populated() -> None:
    from oyst_core.runtime.checksums import load_checksums

    checksums = load_checksums()
    assert checksums["lynis-3.1.7"]
    assert checksums["chkrootkit"]
    assert checksums["rkhunter-1.4.6"]
    assert checksums["unhide-v20240510"]
    assert all(len(v) == 64 for v in checksums.values())


def test_config_roundtrip(tmp_path: Path, monkeypatch: object) -> None:
    from oyst_core import config as cfg_mod

    monkeypatch.setattr(cfg_mod, "config_path", lambda: tmp_path / "config.toml")  # type: ignore[attr-defined]
    save_config(OysterConfig())
    loaded = load_config()
    assert loaded.scan.profile == "quick"


def test_quarantine_add_restore(tmp_path: Path, monkeypatch: object) -> None:
    from oyst_core import config as cfg_mod

    vault_dir = tmp_path / "vault"
    cfg = OysterConfig()
    cfg.quarantine.vault_dir = str(vault_dir)
    monkeypatch.setattr(cfg_mod, "load_config", lambda: cfg)

    sample = tmp_path / "eicar.txt"
    sample.write_text("test file\n", encoding="utf-8")
    vault = QuarantineVault(vault_dir)
    entry = vault.add(str(sample), "test-threat")
    assert not sample.exists()
    restored = vault.restore(entry.id)
    assert restored.exists()


def test_orchestrator_job_lock(tmp_path: Path, monkeypatch: object) -> None:
    from oyst_core import events as ev_mod

    monkeypatch.setattr(ev_mod, "data_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    events = ev_mod.EventLog(tmp_path / "events.db")
    orch = JobOrchestrator(events)
    _result, code = orch.run_scan(profile=ScanProfile.QUICK, paths=[str(tmp_path)])
    assert code in (0, 1, 2, 5)


def test_rpc_server_status() -> None:
    server = RpcServer()
    resp = _rpc_request(server, "status")
    assert "result" in resp
    assert resp["schema_version"] == SCHEMA_VERSION


def test_rpc_history_list() -> None:
    server = RpcServer()
    resp = _rpc_request(server, "history.list", {"limit": 5})
    assert "result" in resp
    assert isinstance(resp["result"], list)


def test_rpc_history_get_missing() -> None:
    server = RpcServer()
    resp = _rpc_request(server, "history.get", {"job_id": "does-not-exist"})
    assert "error" in resp
    assert resp["error"]["code"] == "not_found"


def test_rpc_config_get_set(tmp_path: Path, monkeypatch: object) -> None:
    from oyst_core import config as cfg_mod

    monkeypatch.setattr(cfg_mod, "config_path", lambda: tmp_path / "config.toml")  # type: ignore[attr-defined]
    server = RpcServer()
    resp = _rpc_request(server, "config.get")
    assert "result" in resp
    assert resp["result"]["scan"]["profile"] == "quick"
    _rpc_request(
        server,
        "config.set",
        {"key": "scan.profile", "value": "full"},
        req_id=2,
    )
    resp2 = _rpc_request(
        server,
        "config.get",
        {"key": "scan.profile"},
        req_id=3,
    )
    assert resp2["result"] == "full"


def test_rpc_quarantine_verify() -> None:
    server = RpcServer()
    resp = _rpc_request(server, "quarantine.verify")
    assert resp["result"]["ok"] is True


def test_client_start_scan_shape() -> None:
    from oyst_core.client import OystClient

    client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
    result = client.start_scan(profile="quick", paths=["/tmp"])
    assert "scan" in result
    assert "exit_code" in result


def test_pack_doctor_clamav() -> None:
    from oyst_core.packs.clamav import ClamAVPack

    status = ClamAVPack().doctor()
    assert status.name == "clamav"
