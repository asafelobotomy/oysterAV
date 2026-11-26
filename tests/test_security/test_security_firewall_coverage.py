"""Extra coverage for the firewall in security-gated modules (still @pytest.mark.security)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.firewall import FirewallPack, invalidate_firewall_detect_cache
from oyst_core.packs.firewall_ops import FirewallOps
from oyst_core.privileged import helper_fw_lifecycle as life
from oyst_core.privileged.helper_firewall import _build_firewalld_argv, _build_ufw_argv

pytestmark = pytest.mark.security


# --- validators leftovers ---


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
