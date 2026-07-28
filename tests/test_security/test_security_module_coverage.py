"""Extra coverage for security-gated modules (still @pytest.mark.security)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.audit import SecurityAudit
from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ensure import ensure_firewall_enabled, set_managed_enabled
from oyst_core.packs.firewall_ops import FirewallOps, FirewallResult
from oyst_core.packs.firewall_select import recommended_managed_backend, select_managed_backend
from oyst_core.privileged import helper_fw_lifecycle as life
from oyst_core.privileged.helper_firewall import _build_firewalld_argv, _build_ufw_argv
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


def test_ufw_from_and_default_and_lifecycle() -> None:
    assert (
        _build_ufw_argv(
            ["allow", "--from", "192.0.2.0/24", "--port", "22", "--proto", "tcp"],
        )[0]
        == "ufw"
    )
    assert _build_ufw_argv(["default", "incoming", "deny"]) == [
        "ufw",
        "default",
        "deny",
        "incoming",
    ]
    assert _build_ufw_argv(["default", "allow", "outgoing"]) == [
        "ufw",
        "default",
        "allow",
        "outgoing",
    ]
    assert _build_ufw_argv(["disable"]) == ["ufw", "disable"]
    assert _build_ufw_argv(["reload"]) == ["ufw", "reload"]
    with pytest.raises(ValueError):
        _build_ufw_argv(["default", "incoming"])
    with pytest.raises(ValueError):
        _build_ufw_argv(["default", "sideways", "deny"])


def test_firewalld_service_rich_disable() -> None:
    assert _build_firewalld_argv(["add-service", "ssh"])[0] == "firewall-cmd"
    assert (
        _build_firewalld_argv(
            ["add-rich-rule", "rule", "service", "name=ssh", "accept"],
        )[0]
        == "firewall-cmd"
    )
    assert _build_firewalld_argv(["disable"]) == ["systemctl", "stop", "firewalld"]
    with pytest.raises(ValueError):
        _build_firewalld_argv(["add-port"])


# --- helper_validate ---


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


def test_ensure_as_root_skips_when_active() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"conflict": False, "active": "ufw", "ufw": True},
        ),
    ):
        step = life.ensure_firewall_as_root()
    assert step.get("skipped") is True


def test_ensure_as_root_conflict_and_none() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"conflict": True, "active": "ufw"},
        ),
    ):
        assert life.ensure_firewall_as_root()["ok"] is False
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "conflict": False,
                "active": "none",
                "ufw": False,
                "firewalld": False,
            },
        ),
    ):
        assert life.ensure_firewall_as_root().get("skipped") is True


def test_ensure_as_root_delegates_firewalld() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "conflict": False,
                "active": "none",
                "ufw": False,
                "firewalld": True,
            },
        ),
        patch.object(
            life,
            "_ensure_firewalld",
            return_value={"step": "firewall-ensure", "ok": True},
        ) as ens,
    ):
        life.ensure_firewall_as_root()
    ens.assert_called_once()


def test_select_none_and_missing_backends() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw_active": True,
                "active": "ufw",
                "firewalld_active": False,
                "conflict": False,
            },
        ),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
    ):
        step = life.select_firewall_as_root("none")
    assert step["ok"] is True
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={"ufw": False, "firewalld": False},
        ),
    ):
        assert life.select_firewall_as_root("ufw")["ok"] is False
        assert life.select_firewall_as_root("firewalld")["ok"] is False
    assert life.select_firewall_as_root("bogus")["ok"] is False


def test_family_install_argv_variants() -> None:
    assert "dnf" in life._family_install_argv("fedora", ["ufw"])[0]
    assert "apt-get" in life._family_install_argv("debian", ["ufw"])[0]
    with pytest.raises(ValueError):
        life._family_install_argv("unknown", ["ufw"])
    with pytest.raises(ValueError):
        life._family_install_argv("arch", [])


def test_apply_with_firewall_flag() -> None:
    with patch.object(
        life,
        "ensure_firewall_as_root",
        return_value={"step": "firewall-ensure", "ok": True},
    ) as ens:
        steps = life.apply_firewall_lifecycle_flags(["--with-firewall"])
    assert steps[0]["ok"] is True
    ens.assert_called_once()


def test_install_invalid_backend() -> None:
    step = life.install_firewall_package_as_root("nft")
    assert step["ok"] is False


def test_ufw_status_and_firewalld_ssh_helpers() -> None:
    from oyst_core.packs.firewall_ops import FirewallOps
    from oyst_core.privileged import helper_fw_enable as en

    with patch.object(life, "_run_cmd", side_effect=[(0, "Status: active")]):
        assert "active" in en.ufw_status_text(life._run_cmd)
    with patch.object(life, "_run_cmd", side_effect=[(1, ""), (0, "services: ssh")]):
        with patch.object(FirewallOps, "parse_ssh_open", return_value=True):
            assert en.firewalld_ssh_ok(life._run_cmd) is True


# --- firewall pack ---


def test_firewall_doctor_and_audit_messages() -> None:
    pack = FirewallPack()
    cases = [
        {"active": "ufw", "ufw": True, "conflict": False, "version": "0.36"},
        {"active": "none", "ufw": False, "firewalld": False, "conflict": False, "version": ""},
        {
            "active": "nft-direct",
            "ufw": False,
            "firewalld": False,
            "conflict": False,
            "version": "",
        },
        {"active": "ufw", "ufw": True, "conflict": True, "version": ""},
    ]
    for det in cases:
        with patch.object(pack, "detect", return_value=det):
            status = pack.doctor()
            assert status.message
            audit = pack.audit()
            assert isinstance(audit, list)


def test_firewall_detect_active_backends() -> None:
    invalidate_firewall_detect_cache()
    pack = FirewallPack()

    def which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in {"ufw", "firewall-cmd"} else None

    def run(argv: list[str], timeout: int = 30) -> MagicMock:  # noqa: ARG001
        joined = " ".join(argv)
        if "ufw" in joined and "status" in joined:
            return MagicMock(returncode=0, stdout="Status: active", stderr="")
        if "version" in joined:
            return MagicMock(returncode=0, stdout="ufw 0.36", stderr="")
        return MagicMock(returncode=0, stdout="not running", stderr="")

    with (
        patch("oyst_core.packs.firewall.which", side_effect=which),
        patch("oyst_core.packs.firewall.run_command", side_effect=run),
    ):
        det = pack._detect_uncached()
    assert det["active"] == "ufw"


def test_fail2ban_status_paths() -> None:
    pack = FirewallPack()
    with patch("oyst_core.packs.firewall.which", return_value=None):
        assert pack.fail2ban_status()["installed"] is False
    with (
        patch("oyst_core.packs.firewall.which", return_value="/usr/bin/fail2ban-client"),
        patch(
            "oyst_core.packs.firewall.run_command",
            return_value=MagicMock(returncode=0, stdout="Status", stderr=""),
        ),
    ):
        assert pack.fail2ban_status()["installed"] is True


# --- firewall_ops ---


def test_firewall_ops_mutations_dry_run() -> None:
    ops = FirewallOps()
    with patch.object(ops, "_active_backend", return_value="ufw"):
        assert ops.ufw_rule("allow", port="80", dry_run=True).ok
        assert ops.ufw_default("incoming", "deny", dry_run=True).ok
    with patch.object(ops, "_active_backend", return_value="firewalld"):
        assert ops.firewalld_port("add-port", "443/tcp", dry_run=True).ok
        assert ops.firewalld_service("add-service", "http", dry_run=True).ok
        assert ops.firewalld_rich_rule(
            "add-rich-rule",
            "rule service name=ssh accept",
            dry_run=True,
        ).ok
        assert ops.firewalld_reload(dry_run=True).ok
        assert ops.firewalld_lifecycle("disable", dry_run=True).ok


def test_firewall_ops_snapshot_and_export() -> None:
    ops = FirewallOps()
    with patch(
        "oyst_core.packs.firewall_ops.run_command",
        return_value=MagicMock(returncode=0, stdout="rules", stderr=""),
    ):
        assert ops._snapshot("ufw") == "rules"
        assert ops._snapshot("firewalld") == "rules"
    with patch.object(ops._pack, "detect", return_value={"active": "none"}):
        assert ops.export_rules()["backend"] == "none"


def test_firewall_ops_ssh_allowed_and_plan() -> None:
    ops = FirewallOps()
    with patch.object(ops, "_ufw_rules_text", return_value="22/tcp ALLOW"):
        assert ops._ssh_allowed("ufw") is True
    with (
        patch.object(ops, "_active_backend", return_value="ufw"),
        patch.object(
            ops,
            "_snapshot",
            return_value="a\nb",
        ),
    ):
        diff = ops.plan_diff("b\nc")
    assert "add" in diff


def test_firewall_ops_run_helper_audits() -> None:
    ops = FirewallOps()
    with (
        patch(
            "oyst_core.packs.firewall_ops.run_privileged_helper",
            return_value=MagicMock(returncode=0, stdout="ok", stderr=""),
        ),
        patch.object(ops, "_ufw_rules_text", return_value="after"),
        patch.object(ops, "_audit_mutate") as audit,
        patch("oyst_core.packs.firewall_ops.invalidate_firewall_detect_cache"),
    ):
        result = ops._run_helper("ufw.allow", ["ufw", "allow", "80/tcp"], before="before")
    assert result.ok is True
    audit.assert_called_once()


# --- select / ensure ---


def test_recommended_backend_fedora() -> None:
    with patch("oyst_core.packs.firewall_select.detect_distro_family", return_value="fedora"):
        assert recommended_managed_backend() == "firewalld"


def test_select_invalid_backend() -> None:
    assert select_managed_backend("iptables").ok is False


def test_ensure_rec_firewalld_when_only_fw() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="firewalld",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ok"),
        ) as sel,
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": False,
            "firewalld": True,
        }
        ensure_firewall_enabled()
    assert sel.call_args.args[0] == "firewalld"


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


def test_monitor_mode_empty_part_and_relative() -> None:
    from oyst_core.privileged.validators import validate_monitor_mode

    with pytest.raises(ValueError):
        validate_monitor_mode("/tmp/ok,relative")
    # trailing comma leaves empty part — still ok if others valid
    assert validate_monitor_mode("/tmp/ok,") == "/tmp/ok,"


def test_firewall_ops_active_backend_errors() -> None:
    ops = FirewallOps()
    with patch.object(ops._pack, "detect", return_value={"conflict": True, "active": "ufw"}):
        with pytest.raises(ValueError, match="conflict"):
            ops._active_backend()
    with patch.object(ops._pack, "detect", return_value={"conflict": False, "active": "none"}):
        with pytest.raises(ValueError, match="No active"):
            ops._active_backend()
    with patch.object(
        ops._pack,
        "detect",
        return_value={"conflict": False, "active": "nft-direct"},
    ):
        with pytest.raises(ValueError, match="Unsupported"):
            ops._active_backend()


def test_firewall_ops_ufw_from_and_verbose() -> None:
    ops = FirewallOps()
    with patch.object(ops, "_active_backend", return_value="ufw"):
        r = ops.ufw_rule("allow", port="80", from_addr="192.0.2.1", dry_run=True)
    assert r.ok is True
    assert r.argv is not None
    assert "--from" in r.argv
    with (
        patch.object(ops._pack, "detect", return_value={"active": "ufw"}),
        patch("oyst_core.packs.firewall_ops.which", return_value="/usr/bin/ufw"),
        patch(
            "oyst_core.packs.firewall_ops.run_command",
            return_value=MagicMock(returncode=0, stdout="numbered", stderr=""),
        ),
    ):
        assert ops.verbose_status() == "numbered"


def test_firewall_ops_run_ssh_gate() -> None:
    ops = FirewallOps()
    with (
        patch.object(ops, "_active_backend", return_value="ufw"),
        patch.object(ops, "_snapshot", return_value=""),
        patch.object(ops, "_ssh_allowed", return_value=False),
    ):
        result = ops._run(
            "ufw.enable",
            ["ufw", "enable"],
            require_ssh=True,
            force_lockout=False,
        )
    assert result.ok is False


def test_select_none_stops_firewalld() -> None:
    calls: list[list[str]] = []

    def _run(cmd: list[str]) -> tuple[int, str]:
        calls.append(cmd)
        return 0, "ok"

    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(life, "_run_cmd", side_effect=_run),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw_active": False,
                "firewalld_active": True,
                "active": "firewalld",
                "conflict": False,
            },
        ),
    ):
        step = life.select_firewall_as_root("none")
    assert step["ok"] is True
    assert any(c[:3] == ["systemctl", "stop", "firewalld"] for c in calls)


def test_select_to_firewalld_disables_ufw() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(
            life.FirewallPack,
            "detect",
            side_effect=[
                {
                    "ufw": True,
                    "firewalld": True,
                    "ufw_active": True,
                    "firewalld_active": False,
                    "conflict": False,
                    "active": "ufw",
                },
                {"ufw": True, "firewalld": True, "conflict": False, "active": "none"},
            ],
        ),
        patch.object(
            life,
            "_ensure_firewalld",
            return_value={"step": "firewall-ensure", "ok": True, "message": "ok"},
        ),
    ):
        step = life.select_firewall_as_root("firewalld")
    assert step["ok"] is True


def test_ensure_ufw_force_lockout_skips_ssh_check() -> None:
    with (
        patch(
            "oyst_core.privileged.helper_fw_enable.ufw_status_text",
            return_value="Status: inactive",
        ),
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_ufw(force_lockout=True)
    assert step["ok"] is True


def test_ensure_firewalld_force_lockout() -> None:
    with (
        patch.object(life, "_run_cmd", return_value=(0, "ok")),
        patch.object(life, "invalidate_firewall_detect_cache"),
    ):
        step = life._ensure_firewalld(force_lockout=True)
    assert step["ok"] is True


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


def test_select_already_active_skips() -> None:
    with (
        patch.object(life, "invalidate_firewall_detect_cache"),
        patch.object(
            life.FirewallPack,
            "detect",
            return_value={
                "ufw": True,
                "firewalld": False,
                "ufw_active": True,
                "firewalld_active": False,
                "conflict": False,
                "active": "ufw",
            },
        ),
    ):
        step = life.select_firewall_as_root("ufw")
    assert step.get("skipped") is True


def test_firewall_detect_firewalld_active() -> None:
    invalidate_firewall_detect_cache()
    pack = FirewallPack()

    def which(name: str) -> str | None:
        return "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None

    def run(argv: list[str], timeout: int = 30) -> MagicMock:  # noqa: ARG001
        if "--state" in argv:
            return MagicMock(returncode=0, stdout="running", stderr="")
        if "--version" in argv:
            return MagicMock(returncode=0, stdout="0.9.0", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch("oyst_core.packs.firewall.which", side_effect=which),
        patch("oyst_core.packs.firewall.run_command", side_effect=run),
    ):
        det = pack._detect_uncached()
    assert det["active"] == "firewalld"


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


def test_select_managed_force_lockout_flag() -> None:
    with patch("oyst_core.packs.firewall_select.which", return_value="/usr/bin/ufw"):
        result = select_managed_backend("ufw", dry_run=True, force_lockout=True)
    assert "--force-lockout" in (result.argv or [])


def test_ensure_prefer_ufw_when_rec_fw_missing() -> None:
    with (
        patch("oyst_core.packs.firewall_ensure.FirewallPack") as pack_cls,
        patch("oyst_core.config_access.get_config_value", return_value=None),
        patch(
            "oyst_core.packs.firewall_select.recommended_managed_backend",
            return_value="firewalld",
        ),
        patch(
            "oyst_core.packs.firewall_select.select_managed_backend",
            return_value=FirewallResult(ok=True, message="ok"),
        ) as sel,
    ):
        pack_cls.return_value.detect.return_value = {
            "conflict": False,
            "active": "none",
            "ufw": True,
            "firewalld": False,
        }
        ensure_firewall_enabled()
    assert sel.call_args.args[0] == "ufw"
