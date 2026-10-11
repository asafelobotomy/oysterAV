"""Regression tests for Low-severity privileged-helper audit findings."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.privileged import helper_fail2ban, safe_write
from oyst_core.privileged.validators import (
    rich_rule_ssh_lockout_risk,
    validate_monitor_mode,
    validate_unit,
)

pytestmark = pytest.mark.security

_REPO_ROOT = Path(__file__).resolve().parents[2]


# 1. Rich-rule SSH lockout guard parses the port value.
@pytest.mark.parametrize(
    "rule",
    [
        "rule port port=22 protocol=tcp drop",
        "rule port port=022 protocol=tcp drop",
        "rule port port=0022 protocol=tcp reject",
        "rule port\tport=22\tprotocol=tcp drop",
        "rule family=ipv4 source address=10.0.0.0/8 port port=22 protocol=tcp drop",
        "rule service name=SSH reject",
    ],
)
def test_rich_rule_ssh_lockout_detected(rule: str) -> None:
    assert rich_rule_ssh_lockout_risk(rule) is True


@pytest.mark.parametrize(
    "rule",
    [
        "rule port port=22 protocol=tcp accept",
        "rule port port=2222 protocol=tcp drop",
        "rule port port=220 protocol=tcp drop",
        "rule service name=sshd-alt drop",
    ],
)
def test_rich_rule_ssh_lockout_not_flagged(rule: str) -> None:
    assert rich_rule_ssh_lockout_risk(rule) is False


def test_rich_rule_port_range_bounds_cover_22() -> None:
    from oyst_core.privileged.validators import _rich_rule_port_bounds

    low, high = _rich_rule_port_bounds("20-25")
    assert low <= 22 <= high
    with pytest.raises(ValueError):
        _rich_rule_port_bounds("25-20")


# 2. ensure-fdpass only targets clamonacc units.
def test_ensure_fdpass_rejects_non_clamonacc_unit() -> None:
    from oyst_core.privileged import helper_clamd_unit
    from oyst_core.privileged.helper_clamd import _build_clamd_cocontrol_argv

    with (
        patch.object(helper_clamd_unit, "ensure_host_daily_signatures") as sigs,
        patch.object(helper_clamd_unit, "write_text_nofollow") as write,
        pytest.raises(ValueError, match="fdpass"),
    ):
        _build_clamd_cocontrol_argv(["ensure-fdpass", "--unit=fail2ban"])
    sigs.assert_not_called()
    write.assert_not_called()
    assert helper_clamd_unit.validate_fdpass_unit("clamav-clamonacc") == "clamav-clamonacc"


# 3. fail2ban persist merges with existing persisted IPs.
def test_fail2ban_persist_merges_existing_ips(tmp_path: Path) -> None:
    dropin = tmp_path / "oysterav-sshd-ignore.conf"
    dropin.write_text(
        "[sshd]\nignoreip = 192.0.2.1 bogus 1.2.3.4%x 2001:db8::1\n",
        encoding="utf-8",
    )
    with (
        patch.object(helper_fail2ban, "_JAIL_D", tmp_path),
        patch.object(helper_fail2ban, "_run_fail2ban_client"),
    ):
        helper_fail2ban._persist_fail2ban_ignoreip("sshd", "192.0.2.7")
        helper_fail2ban._persist_fail2ban_ignoreip("sshd", "192.0.2.1")
    assert dropin.read_text(encoding="utf-8") == (
        "[sshd]\nignoreip = 192.0.2.1 2001:db8::1 192.0.2.7\n"
    )


def test_fail2ban_persist_ignores_symlinked_dropin(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("ignoreip = 198.51.100.9\n", encoding="utf-8")
    (tmp_path / "oysterav-sshd-ignore.conf").symlink_to(secret)
    assert helper_fail2ban._existing_ignoreips(tmp_path / "oysterav-sshd-ignore.conf") == []


# 4. clamonacc list files: root-owned under /etc/clamav or caller-owned only.
def test_clamonacc_list_rejects_root_file_outside_etc_clamav() -> None:
    from oyst_core.privileged.helper_validate import _validate_clamonacc_list_path

    passwd = Path("/etc/passwd")
    if not passwd.is_file() or passwd.is_symlink() or passwd.stat().st_uid != 0:
        pytest.skip("needs a root-owned /etc/passwd")
    with pytest.raises(ValueError, match="/etc/clamav"):
        _validate_clamonacc_list_path("--include-list", f"--include-list={passwd}")


def test_clamonacc_list_requires_caller_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core.privileged.helper_validate import _validate_clamonacc_list_path

    if os.getuid() == 0:
        pytest.skip("ownership check needs a non-root test user")
    lst = tmp_path / "include.list"
    lst.write_text("/home/alice\n", encoding="utf-8")
    lst.chmod(0o644)
    monkeypatch.delenv("PKEXEC_UID", raising=False)
    monkeypatch.delenv("SUDO_UID", raising=False)
    with pytest.raises(ValueError, match="caller-owned"):
        _validate_clamonacc_list_path("--include-list", f"--include-list={lst}")
    monkeypatch.setenv("PKEXEC_UID", str(os.getuid() + 1))
    with pytest.raises(ValueError, match="caller-owned"):
        _validate_clamonacc_list_path("--include-list", f"--include-list={lst}")
    monkeypatch.setenv("PKEXEC_UID", str(os.getuid()))
    assert _validate_clamonacc_list_path("--include-list", f"--include-list={lst}").endswith(
        str(lst.resolve())
    )


# 5. OnAccessIncludePath deny-list covers system/package trees.
@pytest.mark.parametrize(
    "path",
    ["/bin", "/sbin/x", "/lib", "/lib64/x", "/usr/lib/x", "/snap/core", "/nix/store"],
)
def test_onaccess_include_denies_system_trees(path: str) -> None:
    from oyst_core.privileged.helper_clamd import _validate_include

    with pytest.raises(ValueError, match="denied"):
        _validate_include(path)


def test_onaccess_include_denies_symlink_into_system(tmp_path: Path) -> None:
    from oyst_core.privileged.helper_clamd import _validate_include

    link = tmp_path / "etc-link"
    link.symlink_to("/etc")
    with pytest.raises(ValueError, match="denied"):
        _validate_include(str(link))


# 6. maldet monitor paths.
@pytest.mark.parametrize(
    "mode",
    [
        "/",
        "/proc",
        "/proc/1",
        "/sys",
        "/dev/shm",
        "/etc",
        "/usr",
        "/run/user",
        "/boot",
        "/does/not/exist/oysterav",
        "/tmp/a b",
        "/tmp/x\tz",
        "/tmp/{a,b}",
        "/tmp/*",
        "/tmp/x\x01",
    ],
)
def test_monitor_mode_rejects_system_and_unsafe(mode: str) -> None:
    with pytest.raises(ValueError):
        validate_monitor_mode(mode)


def test_monitor_mode_rejects_symlink_to_system(tmp_path: Path) -> None:
    link = tmp_path / "proc-link"
    link.symlink_to("/proc")
    with pytest.raises(ValueError, match="protected"):
        validate_monitor_mode(str(link))


def test_monitor_mode_accepts_existing_dir(tmp_path: Path) -> None:
    assert validate_monitor_mode(str(tmp_path)) == str(tmp_path)


# 7. write_text_nofollow is atomic and type-checks before opening.
def test_safe_write_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    errors: list[BaseException] = []

    def _run() -> None:
        try:
            safe_write.write_text_nofollow(fifo, "x")
        except BaseException as exc:  # noqa: BLE001 - captured for assert
            errors.append(exc)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "write blocked on FIFO"
    assert errors and isinstance(errors[0], OSError)


def test_safe_write_refuses_symlink_target_and_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("orig", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(OSError):
        safe_write.write_text_nofollow(link, "evil")
    real_dir = tmp_path / "rd"
    real_dir.mkdir()
    (tmp_path / "ld").symlink_to(real_dir)
    with pytest.raises(OSError):
        safe_write.write_text_nofollow(tmp_path / "ld" / "f", "evil")
    assert real.read_text(encoding="utf-8") == "orig"
    assert not (real_dir / "f").exists()


def test_safe_write_failure_keeps_original(tmp_path: Path) -> None:
    target = tmp_path / "clamd.conf"
    target.write_text("original\n", encoding="utf-8")
    with (
        patch.object(safe_write, "_write_all", side_effect=OSError("disk full")),
        pytest.raises(OSError, match="disk full"),
    ):
        safe_write.write_text_nofollow(target, "new\n")
    assert target.read_text(encoding="utf-8") == "original\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["clamd.conf"]


def test_safe_write_replaces_and_sets_mode(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "rule.rules"
    safe_write.write_text_nofollow(target, "a\n", mode=0o600)
    assert target.read_text(encoding="utf-8") == "a\n"
    assert target.stat().st_mode & 0o7777 == 0o600
    target.chmod(0o640)
    safe_write.write_text_nofollow(target, "b\n", mode=0o644, preserve_mode=True)
    assert target.read_text(encoding="utf-8") == "b\n"
    assert target.stat().st_mode & 0o7777 == 0o640
    safe_write.write_text_nofollow(target, "c\n", mode=0o644)
    assert target.stat().st_mode & 0o7777 == 0o644
    assert sorted(p.name for p in target.parent.iterdir()) == ["rule.rules"]


# 8. Harden reprobe only probes allowlisted clamd units.
def test_harden_reprobe_units_are_allowlisted() -> None:
    from oyst_core.privileged.helper_harden_reprobe import _CLAMD_UNITS

    assert "clamd" not in _CLAMD_UNITS
    for unit in _CLAMD_UNITS:
        assert validate_unit(unit) == unit


# 9. Helper and expire scripts run Python in isolated mode.
def test_helper_scripts_use_isolated_shebang() -> None:
    from oyst_core.privileged.auth_grant_expire import _expire_script_text
    from oyst_core.privileged.install_privileged_helper import (
        HELPER_SCRIPT,
        HELPER_SCRIPT_WITH_SITE,
    )

    assert HELPER_SCRIPT.startswith("#!{python} -I\n")
    assert HELPER_SCRIPT_WITH_SITE.startswith("#!{python} -I\n")
    text = _expire_script_text("/usr/bin/python3", "import sys\nsys.path.insert(0, '/x')")
    assert text.startswith("#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, '/x')\n")
    compile(text, "oyst-auth-expire", "exec")  # no stray indentation


def test_site_insert_works_under_isolated_mode(tmp_path: Path) -> None:
    from oyst_core.privileged.install_privileged_helper import HELPER_SCRIPT_WITH_SITE

    body = HELPER_SCRIPT_WITH_SITE.format(python=sys.executable, site_root=str(_REPO_ROOT))
    probe = body.replace(
        "from oyst_core.privileged.oyst_helper import main\nmain()\n",
        "import oyst_core.privileged.oyst_helper\nprint('ok')\n",
    )
    script = tmp_path / "probe.py"
    script.write_text(probe, encoding="utf-8")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "/nonexistent"}
    proc = subprocess.run(
        [sys.executable, "-I", str(script)],
        capture_output=True,
        text=True,
        cwd="/",
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_expire_python_strips_shebang_flags(tmp_path: Path) -> None:
    from oyst_core.privileged import auth_grant_expire

    helper = tmp_path / "oyst-helper"
    helper.write_text("#!/usr/bin/python3 -I\nmain()\n", encoding="utf-8")
    real_path = Path

    def _fake_path(arg: object, *rest: object) -> Path:
        if arg == "/usr/lib/oysterav/oyst-helper":
            return helper
        return real_path(arg, *rest)  # type: ignore[arg-type]

    with patch.object(auth_grant_expire, "Path", _fake_path):
        assert auth_grant_expire._resolve_expire_python() == "/usr/bin/python3"


# 10. Batch delete labels show the source address.
def test_ufw_batch_delete_label_includes_source() -> None:
    from oyst_core.privilege.recipes_firewall import _rule_label

    rule = {"action": "delete", "rule_action": "allow", "port": "22", "from_addr": "10.0.0.5"}
    assert _rule_label(rule, 1) == "1. Delete allow 22/tcp from 10.0.0.5"
    assert _rule_label({"action": "delete", "port": "80"}, 2) == "2. Delete allow 80/tcp"
