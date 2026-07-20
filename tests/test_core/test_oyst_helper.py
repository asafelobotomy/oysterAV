"""Tests for oyst-helper validators and subcommands."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from oyst_core.privileged.oyst_helper import (
    _build_fail2ban_argv,
    _build_firewall_argv,
    _build_systemctl_argv,
    _build_ufw_argv,
    run_helper_argv,
)
from oyst_core.privileged.validators import (
    validate_ip,
    validate_jail,
    validate_monitor_mode,
    validate_port,
)


def test_validate_ip_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        validate_ip("not-an-ip")


def test_validate_jail_rejects_shell() -> None:
    with pytest.raises(ValueError):
        validate_jail("sshd; rm -rf /")


def test_build_ufw_allow_argv() -> None:
    argv = _build_ufw_argv(["allow", "--port", "22", "--proto", "tcp"])
    assert argv == ["ufw", "allow", "to", "any", "port", "22", "tcp"]


def test_build_fail2ban_unban_argv() -> None:
    argv = _build_fail2ban_argv(["unban", "192.0.2.1"])
    assert argv == ["fail2ban-client", "unban", "192.0.2.1"]


def test_build_fail2ban_unban_flow_runs_compound(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        _ = kwargs
        calls.append(list(argv))
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def fake_persist(jail: str, ip: str) -> None:
        calls.append(["persist-ignoreip", jail, ip])

    monkeypatch.setattr(
        "oyst_core.privileged.helper_fail2ban.subprocess.run",
        fake_run,
    )
    monkeypatch.setattr(
        "oyst_core.privileged.helper_fail2ban._persist_fail2ban_ignoreip",
        fake_persist,
    )
    assert _build_fail2ban_argv(
        ["unban-flow", "192.0.2.1", "--jail", "sshd", "--ignore", "--persist"]
    ) == ["true"]
    assert calls[0] == ["fail2ban-client", "set", "sshd", "unbanip", "192.0.2.1"]
    assert calls[1] == ["fail2ban-client", "set", "sshd", "addignoreip", "192.0.2.1"]
    assert calls[2] == ["persist-ignoreip", "sshd", "192.0.2.1"]


def test_build_fail2ban_unban_flow_requires_jail_for_ignore() -> None:
    with pytest.raises(ValueError, match="--jail"):
        _build_fail2ban_argv(["unban-flow", "192.0.2.1", "--ignore"])


def test_maldet_start_monitor_one_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.privileged.oyst_helper import _build_maldet_config_argv

    applied: list[str] = []
    systemctl: list[list[str]] = []

    def fake_apply(mode: str) -> None:
        applied.append(mode)

    def fake_run(argv: list[str], **kwargs: object) -> object:
        _ = kwargs
        systemctl.append(list(argv))
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(
        "oyst_core.privileged.helper_services._apply_maldet_monitor_mode",
        fake_apply,
    )
    monkeypatch.setattr(
        "oyst_core.privileged.helper_services.subprocess.run",
        fake_run,
    )
    assert _build_maldet_config_argv(["start-monitor", "users"]) == ["true"]
    assert applied == ["users"]
    assert systemctl == [["systemctl", "enable", "--now", "maldet"]]


def test_build_systemctl_rejects_unknown_unit() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        _build_systemctl_argv(["start", "nginx.service"])


def test_build_systemctl_clamd_argv() -> None:
    argv = _build_systemctl_argv(["enable-now", "clamav-daemon"])
    assert argv == ["systemctl", "enable", "--now", "clamav-daemon"]


def test_build_firewall_firewalld_add_port() -> None:
    argv = _build_firewall_argv(["firewalld", "add-port", "443/tcp", "--zone", "public"])
    assert "--add-port=443/tcp" in argv[1]
    assert "--permanent" in argv


def test_oyst_helper_rejects_unknown_command() -> None:
    assert run_helper_argv(["run", "curl", "http://example.com"]) != 0


def test_oyst_helper_allows_loginctl_linger() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    assert _validate_run_argv(["loginctl", "enable-linger", "alice"]) == [
        "loginctl",
        "enable-linger",
        "alice",
    ]
    assert _validate_run_argv(["loginctl", "disable-linger", "alice"]) == [
        "loginctl",
        "disable-linger",
        "alice",
    ]


def test_oyst_helper_allows_clamonacc_fdpass(tmp_path: Path) -> None:
    from oyst_core.privileged.oyst_helper import _validate_scanner_argv

    include = tmp_path / "include.list"
    include.write_text("/home/alice/Downloads\n", encoding="utf-8")
    exclude = tmp_path / "exclude.list"
    exclude.write_text("/home/alice/.cache\n", encoding="utf-8")
    argv = _validate_scanner_argv(
        "clamonacc",
        [
            "/usr/bin/clamonacc",
            "--foreground",
            "--fdpass",
            f"--include-list={include}",
            f"--exclude-list={exclude}",
        ],
    )
    assert argv[0] == "clamonacc"
    assert "--foreground" in argv
    assert "--fdpass" in argv
    assert any(a.startswith("--include-list=") for a in argv)
    assert any(a.startswith("--exclude-list=") for a in argv)


def test_oyst_helper_rejects_bad_linger_user() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    with pytest.raises(ValueError, match="invalid username"):
        _validate_run_argv(["loginctl", "enable-linger", "alice;rm"])


def test_oyst_helper_rejects_pacman_remove() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    with pytest.raises(ValueError, match="only allows"):
        _validate_run_argv(["pacman", "-Rns", "clamav"])


def test_oyst_helper_allows_pacman_install() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    assert _validate_run_argv(["pacman", "-Sy", "--noconfirm", "clamav"]) == [
        "pacman",
        "-Sy",
        "--noconfirm",
        "clamav",
    ]


def test_oyst_helper_allows_rkhunter_propupd() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    assert _validate_run_argv(["rkhunter", "--propupd"]) == ["rkhunter", "--propupd"]


def test_oyst_helper_rejects_aur_helpers_as_root_run() -> None:
    from oyst_core.privileged.oyst_helper import _validate_run_argv

    with pytest.raises(ValueError, match="not allowlisted"):
        _validate_run_argv(["paru", "-S", "--noconfirm", "foo"])


def test_oyst_helper_install_script_requires_maldetect_dir(tmp_path: Path) -> None:
    from oyst_core.privileged.oyst_helper import _validate_install_script

    bad = tmp_path / "install.sh"
    bad.write_text("#!/bin/bash\n", encoding="utf-8")
    with pytest.raises(ValueError, match="maldetect-"):
        _validate_install_script(str(bad))


def test_oyst_helper_install_script_requires_oyst_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import oyst_helper

    # Simulate /tmp/oyst-maldet-xxx/extract/maldetect-1.6.6/install.sh
    root = Path("/tmp")
    work = root / "oyst-maldet-test"
    extract = work / "extract" / "maldetect-1.6.6"
    extract.mkdir(parents=True, exist_ok=True)
    good = extract / "install.sh"
    good.write_text("#!/bin/bash\n", encoding="utf-8")
    try:
        assert oyst_helper._validate_install_script(str(good)) == good.resolve()
    finally:
        shutil.rmtree(work, ignore_errors=True)

    outside = tmp_path / "maldetect-1.6.6"
    outside.mkdir()
    outside_script = outside / "install.sh"
    outside_script.write_text("#!/bin/bash\n", encoding="utf-8")
    with pytest.raises(ValueError, match="oyst-maldet-"):
        oyst_helper._validate_install_script(str(outside_script))


def test_validate_port_range() -> None:
    assert validate_port("22") == "22"
    with pytest.raises(ValueError):
        validate_port("99999")


def test_validate_monitor_mode_rejects_quotes() -> None:
    with pytest.raises(ValueError, match="disallowed"):
        validate_monitor_mode('/tmp/evil"; evil=1 #')


def test_sanitize_on_calendar_rejects_injection() -> None:
    from oyst_core.schedule_util import sanitize_on_calendar

    with pytest.raises(ValueError, match="newlines"):
        sanitize_on_calendar("daily\n\n[Service]\nExecStart=/bin/evil")
    with pytest.raises(ValueError, match="section"):
        sanitize_on_calendar("daily [Service]")
    assert sanitize_on_calendar("*-*-* 03:00:00") == "*-*-* 03:00:00"
