"""Extra coverage for security-gated modules (still @pytest.mark.security)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.audit import SecurityAudit
from oyst_core.packs.firewall_ensure import set_managed_enabled
from oyst_core.privileged import helper_fw_lifecycle as life
from oyst_core.privileged.helper_validate import (
    _validate_install_script,
    _validate_run_argv,
    open_install_script_fd,
)
from oyst_core.privileged.validators import (
    validate_passwordless_systemctl_action,
    validate_passwordless_unit,
    validate_port_spec,
    validate_systemctl_action,
    validate_unit,
)
from oyst_core.rpc_auth import ensure_rpc_token, load_rpc_token, verify_rpc_token

pytestmark = pytest.mark.security


# --- validators leftovers ---


def test_validate_unit_and_systemctl_actions() -> None:
    assert validate_unit("fail2ban") == "fail2ban"
    with pytest.raises(ValueError):
        validate_unit("evil.service")
    assert validate_systemctl_action("restart") == "restart"
    with pytest.raises(ValueError):
        validate_systemctl_action("mask")
    assert validate_port_spec("443/tcp") == "443/tcp"
    assert validate_port_spec("80") == "80"


def test_passwordless_validators() -> None:
    # Units/actions depend on auth_grant_scope allowlists.
    with pytest.raises(ValueError):
        validate_passwordless_unit("not-a-unit")
    with pytest.raises(ValueError):
        validate_passwordless_systemctl_action("mask")


# --- helper_firewall branches ---


def test_validate_run_argv_scanners_and_pms() -> None:
    assert _validate_run_argv(["chkrootkit"]) == ["chkrootkit"]
    assert _validate_run_argv(["rkhunter", "--check", "--sk"])[0] == "rkhunter"
    assert _validate_run_argv(["dnf", "install", "-y", "ufw"])[-1] == "ufw"
    assert _validate_run_argv(["apt-get", "install", "-y", "ufw"])[-1] == "ufw"
    with pytest.raises(ValueError):
        _validate_run_argv(["rkhunter", "--evil"])
    with pytest.raises(ValueError):
        _validate_run_argv(["lynis", "audit", "system", "--evil"])


def test_validate_lynis_and_clamonacc_shapes() -> None:
    assert _validate_run_argv(
        ["lynis", "audit", "system", "--quick", "--no-colors"],
    )[:3] == ["lynis", "audit", "system"]
    assert (
        _validate_run_argv(
            ["clamonacc", "--foreground", "--fdpass"],
        )[0]
        == "clamonacc"
    )
    with pytest.raises(ValueError):
        _validate_run_argv(["clamonacc", "--fdpass"])


def test_install_script_validation(tmp_path: Path) -> None:
    root = tmp_path / "oyst-maldet-abc" / "maldetect-1.0"
    root.mkdir(parents=True)
    script = root / "install.sh"
    body = b"#!/bin/sh\necho ok\n"
    script.write_bytes(body)
    # Must be under /tmp or /var/tmp — relocate via symlink into tmp.
    real_tmp = Path("/tmp") / f"oyst-maldet-sec-{os.getpid()}"
    try:
        if real_tmp.exists():
            import shutil

            shutil.rmtree(real_tmp)
        real_tmp.mkdir()
        md = real_tmp / "maldetect-1.0"
        md.mkdir()
        target = md / "install.sh"
        target.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        assert _validate_install_script(str(target), digest) == target.resolve()
        fd = open_install_script_fd(str(target), digest)
        os.close(fd)
        with pytest.raises(ValueError):
            open_install_script_fd(str(target), "0" * 64)
    finally:
        import shutil

        if real_tmp.exists():
            shutil.rmtree(real_tmp)


# --- helper_fw_lifecycle remaining paths ---


def test_set_managed_enabled_conflict() -> None:
    with patch("oyst_core.packs.firewall_ensure.FirewallOps") as ops_cls:
        ops_cls.return_value._pack.detect.return_value = {"conflict": True, "active": "ufw"}
        result = set_managed_enabled(False)
    assert result.ok is False


# --- rpc_auth leftovers ---


def test_load_and_race_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    assert load_rpc_token() is None
    token = ensure_rpc_token()
    assert load_rpc_token() == token
    verify_rpc_token(token)
    # Existing empty file path → recreate
    (tmp_path / "oyst.token").write_text("\n", encoding="utf-8")
    token2 = ensure_rpc_token()
    assert token2


# --- audit leftovers ---


def test_audit_list_and_chmod(tmp_path: Path) -> None:
    audit = SecurityAudit(db_path=tmp_path / "e.db")
    audit.log("config.set", "k", success=True, data={"v": 1})
    entries = audit.list_entries(limit=10)
    assert entries
    assert (tmp_path / "e.db").stat().st_mode & 0o777 == 0o600


# --- push coverage over 85% ---


def test_validate_run_argv_reject_edges() -> None:
    with pytest.raises(ValueError):
        _validate_run_argv(["pacman", "-Rns", "ufw"])
    with pytest.raises(ValueError):
        _validate_run_argv(["pacman", "-Sy", "--noconfirm"])
    with pytest.raises(ValueError):
        _validate_run_argv(["dnf", "remove", "-y", "ufw"])
    with pytest.raises(ValueError):
        _validate_run_argv(["dnf", "install", "-y"])
    with pytest.raises(ValueError):
        _validate_run_argv(["apt", "install", "-y"])
    with pytest.raises(ValueError):
        _validate_run_argv(["chkrootkit", "-q"])
    with pytest.raises(ValueError):
        _validate_run_argv(["rkhunter"])
    with pytest.raises(ValueError):
        _validate_run_argv(["rkhunter", "--sk"])
    with pytest.raises(ValueError):
        _validate_run_argv(["unhide"])
    assert _validate_run_argv(["unhide", "proc"]) == ["unhide", "proc"]
    with pytest.raises(ValueError):
        _validate_run_argv(["loginctl", "list-users"])


def test_resolve_trusted_binary_rejects_bad_names() -> None:
    from oyst_core.privileged.helper_validate import resolve_trusted_argv, resolve_trusted_binary

    with pytest.raises(ValueError):
        resolve_trusted_binary("")
    with pytest.raises(ValueError):
        resolve_trusted_binary("..")
    # Empty argv passthrough
    assert resolve_trusted_argv([]) == []


def test_is_root_owned_file_rejects_group_writable(tmp_path: Path) -> None:
    from oyst_core.privileged import helper_validate as hv

    target = tmp_path / "tool"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o775)
    assert hv._is_root_owned_file(target) is False


def test_passwordless_accept() -> None:
    assert validate_passwordless_unit("maldet") == "maldet"
    assert validate_passwordless_systemctl_action("start") == "start"
    with pytest.raises(ValueError):
        validate_passwordless_unit("fail2ban")  # allowlisted unit, not passwordless
    with pytest.raises(ValueError):
        validate_passwordless_systemctl_action("stop")


def test_monitor_mode_empty_part_and_relative(tmp_path: Path) -> None:
    from oyst_core.privileged.validators import validate_monitor_mode

    with pytest.raises(ValueError):
        validate_monitor_mode(f"{tmp_path},relative")
    # trailing comma leaves empty part — still ok if others valid
    assert validate_monitor_mode(f"{tmp_path},") == f"{tmp_path},"


def test_run_cmd_and_secure_env() -> None:
    env = life._secure_env()
    assert env["PATH"].startswith("/usr/bin")
    with (
        patch.object(life, "resolve_trusted_argv", side_effect=lambda c: c),
        patch(
            "oyst_core.privileged.helper_fw_lifecycle.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="ok", stderr=""),
        ),
    ):
        rc, out = life._run_cmd(["true"])
    assert rc == 0
    assert out == "ok"


def test_rpc_peercred_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.rpc_auth import verify_peer_credentials
    from oyst_core.rpc_errors import RpcAuthError

    monkeypatch.setattr("oyst_core.rpc_auth.data_dir", lambda: tmp_path)
    tmp_path.mkdir(exist_ok=True)
    ensure_rpc_token()
    conn = MagicMock()
    conn.getsockopt.side_effect = OSError("no peercred")
    with pytest.raises(RpcAuthError, match="peer credentials"):
        verify_peer_credentials(conn)
