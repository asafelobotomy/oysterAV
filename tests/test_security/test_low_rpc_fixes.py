"""Regression tests for Low-severity RPC audit findings."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from oyst_core import rpc_auth
from oyst_core.rpc_auth import ensure_rpc_token, load_rpc_token, verify_rpc_token
from oyst_core.rpc_errors import RpcAuthError, RpcNotFoundError, RpcValidationError
from oyst_core.rpc_handlers import dispatch_rpc
from oyst_core.rpc_handlers.params import (
    LIMIT_MAX,
    loggable_params,
    opt_bool,
    opt_limit,
    req_int,
    req_str,
)
from oyst_core.serve import RpcServer

pytestmark = pytest.mark.security


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> RpcServer:
    monkeypatch.setattr("oyst_core.serve.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    return RpcServer(tmp_path / "rpc.sock")


def _call(server: RpcServer, method: str, params: Any) -> dict[str, Any]:
    token = ensure_rpc_token()
    return server.handle({"method": method, "params": params, "id": 1, "auth": token})


# --- 1. non-ASCII token -------------------------------------------------------


@pytest.mark.parametrize("bad", ["tökén-" * 8, "\udcff" * 30, "é", 12345])
def test_verify_rpc_token_odd_input_is_auth_failed(
    bad: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    ensure_rpc_token()
    with pytest.raises(RpcAuthError):
        verify_rpc_token(bad)


def test_server_non_ascii_token_returns_auth_failed(server: RpcServer) -> None:
    ensure_rpc_token()
    resp = server.handle({"method": "status", "params": {}, "id": 1, "auth": "ü" * 40})
    assert resp["error"]["code"] == "auth_failed"


# --- 2. typed params ----------------------------------------------------------


def test_param_helpers_raise_validation_error() -> None:
    with pytest.raises(RpcValidationError):
        req_int({}, "id")
    with pytest.raises(RpcValidationError):
        req_int({"id": "abc"}, "id")
    with pytest.raises(RpcValidationError):
        req_int({"id": True}, "id")
    with pytest.raises(RpcValidationError):
        req_str({"path": ["x"]}, "path")
    with pytest.raises(RpcValidationError):
        opt_bool({"force": "maybe"}, "force")
    assert req_int({"id": "7"}, "id") == 7
    assert opt_bool({"force": "true"}, "force") is True


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("quarantine.restore", {}),
        ("quarantine.restore", {"id": "not-int"}),
        ("quarantine.delete", {"id": [1]}),
        ("config.set", {"key": "ui.theme"}),
        ("runtime.remove", {}),
        ("fail2ban.unban", {}),
        ("clamonacc.add_path", {"path": {"x": 1}}),
        ("pack.install", {}),
        ("job.start", {"profile": "bogus"}),
        ("history.list", {"limit": "lots"}),
    ],
)
def test_bad_params_are_validation_errors(server: RpcServer, method: str, params: Any) -> None:
    resp = _call(server, method, params)
    assert resp["error"]["code"] == "validation_error", resp


def test_unknown_quarantine_id_is_not_found(tmp_path: Path) -> None:
    with patch("oyst_core.rpc_handlers.data.QuarantineVault") as vault_cls:
        vault_cls.return_value.get.return_value = None
        with pytest.raises(RpcNotFoundError):
            dispatch_rpc("quarantine.restore", {"id": 99, "dry_run": True})
        vault_cls.return_value.restore.assert_not_called()


def test_config_set_bad_value_is_validation_error(server: RpcServer) -> None:
    with patch(
        "oyst_core.rpc_handlers.config_schedule.set_config_value",
        side_effect=KeyError("bad value"),
    ):
        resp = _call(server, "config.set", {"key": "ui.theme", "value": "x"})
    assert resp["error"]["code"] == "validation_error"


# --- 3. fail2ban.jail validates the name ---------------------------------------


@pytest.mark.parametrize(
    "method", ["fail2ban.jail", "fail2ban.jail_enable", "fail2ban.jail_disable"]
)
def test_fail2ban_jail_name_validated(method: str) -> None:
    with patch("oyst_core.packs.fail2ban.Fail2banPack") as pack_cls:
        with pytest.raises(RpcValidationError):
            dispatch_rpc(method, {"name": "sshd; rm -rf /"})
        pack_cls.return_value.jail_status.assert_not_called()
        pack_cls.return_value.set_jail_enabled.assert_not_called()


# --- 4. limit clamped ------------------------------------------------------------


@pytest.mark.parametrize(("raw", "expected"), [(-1, 1), (0, 1), (5, 5), (10**9, LIMIT_MAX)])
def test_opt_limit_clamps(raw: int, expected: int) -> None:
    assert opt_limit({"limit": raw}, 20) == expected
    assert opt_limit({}, 20) == 20


@pytest.mark.parametrize("method", ["history.list", "audit.list"])
def test_history_and_audit_limit_clamped(method: str) -> None:
    event_log = MagicMock()
    audit = MagicMock()
    dispatch_rpc(method, {"limit": -1}, event_log=event_log, audit=audit)
    called = event_log.history if method == "history.list" else audit.list_entries
    assert called.call_args.kwargs["limit"] == 1


# --- 5. param redaction in transcript ---------------------------------------------


def test_config_set_value_redacted_and_large_params_truncated() -> None:
    redacted = loggable_params("config.set", {"key": "ui.theme", "value": "s3cret"})
    assert redacted == {"key": "ui.theme", "value": "[redacted]"}
    big = loggable_params("quarantine.add", {"path": "x" * 10_000, "items": list(range(500))})
    assert len(big["path"]) < 1000
    assert len(big["items"]) <= 51


def test_dispatch_logs_redacted_params() -> None:
    with (
        patch("oyst_core.terminal_log.log_rpc_call") as log_call,
        patch("oyst_core.rpc_handlers.config_schedule.set_config_value"),
    ):
        dispatch_rpc("config.set", {"key": "ui.theme", "value": "s3cret"})
    logged = log_call.call_args.args[1]
    assert "s3cret" not in repr(logged)
    assert logged["key"] == "ui.theme"


# --- 6. token creation is atomic, no symlink follow --------------------------------


def test_token_concurrent_creation_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    results: list[str] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()
        results.append(ensure_rpc_token())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(results)) == 1
    path = tmp_path / "oyst.token"
    assert path.stat().st_mode & 0o777 == 0o600
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".oyst.token.")]


def test_token_symlink_not_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    target = tmp_path / "victim"
    target.write_text("A" * 40)
    (tmp_path / "oyst.token").symlink_to(target)
    with pytest.raises(OSError):
        ensure_rpc_token()
    assert load_rpc_token() is None
    assert target.read_text() == "A" * 40


def test_short_token_file_replaced_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    monkeypatch.setattr(rpc_auth, "_READ_RETRY_DELAY_S", 0)
    path = tmp_path / "oyst.token"
    path.write_text("short")
    old_ino = path.stat().st_ino
    token = ensure_rpc_token()
    assert len(token) >= 22
    assert path.read_text().strip() == token
    assert os.stat(path).st_ino != old_ino  # replaced, not truncated in place
