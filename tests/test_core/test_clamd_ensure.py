"""Tests for ADR-008 Phase 4 clamd co-control ensures."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.packs.clamd_ensure import (
    ensure_fdpass,
    ensure_prevention,
    ensure_virusevent,
    fdpass_status,
)
from oyst_core.privileged.helper_clamd import (
    _build_clamd_cocontrol_argv,
    _replace_marked_block,
    _validate_include,
)


def test_replace_marked_block_append_and_update() -> None:
    text = "User clamav\n"
    updated = _replace_marked_block(
        text,
        "# oysterAV VirusEvent begin",
        "# oysterAV VirusEvent end",
        ["VirusEvent /tmp/oyst-virusevent"],
    )
    assert "# oysterAV VirusEvent begin" in updated
    assert "VirusEvent /tmp/oyst-virusevent" in updated
    again = _replace_marked_block(
        updated,
        "# oysterAV VirusEvent begin",
        "# oysterAV VirusEvent end",
        ["VirusEvent /tmp/oyst-virusevent-2"],
    )
    assert "VirusEvent /tmp/oyst-virusevent-2" in again
    assert "VirusEvent /tmp/oyst-virusevent\n" not in again
    assert again.count("# oysterAV VirusEvent begin") == 1


def test_validate_include_denies_system_roots() -> None:
    for path in (
        "/",
        "/etc",
        "/var/tmp",
        "/tmp",
        "/tmp/x",
        "/opt",
        "/mnt",
        "/media",
        "/srv",
        "/home",
    ):
        with pytest.raises(ValueError, match="denied|invalid"):
            _validate_include(path)
    assert _validate_include("/home/user/Downloads") == "/home/user/Downloads"


def test_ensure_fdpass_requires_confirm() -> None:
    assert ensure_fdpass(confirm=False)["ok"] is False


def test_ensure_fdpass_skips_without_unit() -> None:
    with patch("oyst_core.packs.clamd_ensure.ClamonaccPack") as pack_cls:
        pack_cls.return_value._systemd_unit.return_value = None
        result = ensure_fdpass(confirm=True)
    assert result["ok"] is True
    assert result.get("skipped") is True


def test_ensure_fdpass_calls_helper() -> None:
    with (
        patch("oyst_core.packs.clamd_ensure.ClamonaccPack") as pack_cls,
        patch("oyst_core.packs.clamd_ensure.fdpass_status", return_value={"fdpass": False}),
        patch("oyst_core.packs.clamd_ensure.run_privileged_helper") as helper,
        patch("oyst_core.packs.clamd_ensure.SecurityAudit"),
    ):
        pack_cls.return_value._systemd_unit.return_value = "clamav-clamonacc"
        helper.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = ensure_fdpass(confirm=True)
    assert result["ok"] is True
    helper.assert_called_once()
    assert helper.call_args.args[0] == "clamd-cocontrol"


def test_fdpass_status_process_mode() -> None:
    with patch("oyst_core.packs.clamd_ensure.ClamonaccPack") as pack_cls:
        pack_cls.return_value._systemd_unit.return_value = None
        status = fdpass_status()
    assert status["unit"] is None
    assert status["fdpass"] is False


def test_ensure_virusevent_handoff() -> None:
    with (
        patch("oyst_core.packs.clamd_ensure.install_wrapper", return_value={"ok": True}),
        patch(
            "oyst_core.packs.clamd_ensure.virusevent_status",
            return_value={"handoff": True, "message": "foreign"},
        ),
    ):
        result = ensure_virusevent(confirm=True)
    assert result["ok"] is False
    assert result.get("handoff") is True


def test_ensure_prevention_requires_preference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    from oyst_core.config import load_config, save_config

    cfg = load_config()
    cfg.clamonacc.prevention = False
    save_config(cfg)
    result = ensure_prevention(confirm=True)
    assert result["ok"] is False
    assert "prevention" in str(result.get("error", "")).lower()


def test_ensure_prevention_chains_fdpass_when_unit_present(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    from oyst_core.config import load_config, save_config

    cfg = load_config()
    cfg.clamonacc.prevention = True
    cfg.clamonacc.paths = ["/home/testuser/Downloads"]
    save_config(cfg)
    probe = {
        "classification": "permissive",
        "mount_paths": [],
        "conf_path": "/etc/clamav/clamd.conf",
        "user": "clamav",
        "local_socket": None,
    }
    with (
        patch("oyst_core.packs.clamd_ensure.probe_onaccess_prevention", return_value=probe),
        patch(
            "oyst_core.packs.clamd_ensure.run_privileged_helper",
            return_value=MagicMock(returncode=0, stdout="ok", stderr=""),
        ),
        patch("oyst_core.packs.clamd_ensure.SecurityAudit"),
        patch("oyst_core.packs.clamd_ensure.ClamonaccPack") as pack_cls,
        patch(
            "oyst_core.packs.clamd_ensure.ensure_fdpass",
            return_value={"ok": True, "changed": True},
        ) as fdpass,
        patch("oyst_core.packs.clamd_ensure._allowed_include", return_value=True),
        patch("oyst_core.packs.clamd_ensure._append_restart_flags"),
    ):
        pack_cls.return_value._systemd_unit.return_value = "clamav-clamonacc"
        result = ensure_prevention(confirm=True)
    assert result["ok"] is True
    assert result.get("fdpass", {}).get("ok") is True
    fdpass.assert_called_once_with(confirm=True)


def test_helper_ensure_virusevent_writes_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\n", encoding="utf-8")
    # Helper validates /etc paths — monkeypatch validator by calling internals.
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    monkeypatch.setattr(
        mod, "_ensure_system_wrapper", lambda: Path("/usr/lib/oysterav/oyst-virusevent")
    )
    monkeypatch.setattr(mod, "_validate_wrapper_cmd", lambda raw: raw)
    monkeypatch.setattr(mod, "restart_clam_stack", lambda *_a, **_k: None)
    wrapper = "/usr/lib/oysterav/oyst-virusevent"
    _build_clamd_cocontrol_argv(
        ["ensure-virusevent", f"--conf={conf}", f"--cmd={wrapper}"],
    )
    text = conf.read_text(encoding="utf-8")
    assert "VirusEvent " in text
    assert "oyst-virusevent" in text
    assert (
        conf.with_name(conf.name + ".oysterav-bak").is_file()
        or Path(
            str(conf) + ".oysterav-bak",
        ).is_file()
    )


def test_helper_ensure_prevention_refuses_mountpath(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\nOnAccessMountPath /\n", encoding="utf-8")
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    with pytest.raises(ValueError, match="MountPath"):
        _build_clamd_cocontrol_argv(
            [
                "ensure-prevention",
                f"--conf={conf}",
                "--user=clamav",
                "--include=/home/u/Downloads",
            ],
        )


def test_helper_ensure_prevention_refuses_foreign_onaccess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text(
        "User clamav\nOnAccessIncludePath /home/u/Downloads\nOnAccessPrevention yes\n",
        encoding="utf-8",
    )
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    with pytest.raises(ValueError, match="foreign OnAccessIncludePath"):
        _build_clamd_cocontrol_argv(
            [
                "ensure-prevention",
                f"--conf={conf}",
                "--user=clamav",
                "--include=/home/u/Downloads",
            ],
        )


def test_helper_ensure_prevention_replaces_oyster_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text(
        "User clamav\n"
        "# oysterAV OnAccess begin\n"
        "OnAccessIncludePath /home/u/old\n"
        "OnAccessPrevention yes\n"
        "OnAccessExcludeUname clamav\n"
        "# oysterAV OnAccess end\n",
        encoding="utf-8",
    )
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    monkeypatch.setattr(mod, "restart_clam_stack", lambda *_a, **_k: None)
    _build_clamd_cocontrol_argv(
        [
            "ensure-prevention",
            f"--conf={conf}",
            "--user=clamav",
            "--include=/home/u/Downloads",
        ],
    )
    text = conf.read_text(encoding="utf-8")
    assert "OnAccessIncludePath /home/u/Downloads" in text
    assert "/home/u/old" not in text


def test_write_text_nofollow_preserve_mode(tmp_path: Path) -> None:
    from oyst_core.privileged.safe_write import write_text_nofollow

    target = tmp_path / "clamd.conf"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o640)
    write_text_nofollow(target, "new\n", mode=0o644, preserve_mode=True)
    assert target.read_text(encoding="utf-8") == "new\n"
    assert target.stat().st_mode & 0o777 == 0o640


def test_parse_systemctl_exec_start_preserves_vendor_flags() -> None:
    from oyst_core.privileged.helper_clamd_unit import (
        build_fdpass_dropin_body,
        parse_systemctl_exec_start,
    )

    raw = (
        "{ path=/usr/bin/clamonacc ; "
        "argv[]=/usr/bin/clamonacc -F --config-file=/etc/clamav/clamd.conf ; "
        "ignore_errors=no }"
    )
    argv = parse_systemctl_exec_start(raw)
    assert argv[0] == "/usr/bin/clamonacc"
    assert "--config-file=/etc/clamav/clamd.conf" in argv
    body = build_fdpass_dropin_body(argv)
    assert "--fdpass" in body
    assert "--config-file=/etc/clamav/clamd.conf" in body


def test_ensure_fdpass_dropin_fails_closed_on_bad_vendor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    monkeypatch.setattr(unit, "ensure_host_daily_signatures", lambda: "signatures present")
    monkeypatch.setattr(unit, "_unit_file_listed", lambda *_a, **_k: False)
    monkeypatch.setattr(unit, "_systemctl_show", lambda *_a, **_k: "argv[]=/bin/evil -x ;")
    monkeypatch.setattr(unit, "validate_unit", lambda u: u)
    with pytest.raises(ValueError, match="refusing stripped fdpass"):
        unit.ensure_fdpass_dropin("clamav-clamonacc")


def test_ensure_fdpass_dropin_minimal_when_no_vendor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    dropin_dir = tmp_path / "clamav-clamonacc.service.d"
    real_path = Path

    def _path(arg: object) -> Path:
        text = str(arg)
        if text.startswith("/etc/systemd/system/") and text.endswith(".service.d"):
            return dropin_dir
        return real_path(arg)

    monkeypatch.setattr(unit, "Path", _path)
    monkeypatch.setattr(unit, "ensure_host_daily_signatures", lambda: "signatures present")
    monkeypatch.setattr(unit, "_unit_file_listed", lambda *_a, **_k: False)
    monkeypatch.setattr(unit, "_systemctl_show", lambda *_a, **_k: "")
    monkeypatch.setattr(unit, "validate_unit", lambda u: u)
    monkeypatch.setattr(unit, "_resolve_clamonacc_bin", lambda: "/usr/bin/clamonacc")
    monkeypatch.setattr(unit, "_run_systemctl", lambda *_a, **_k: None)
    unit.ensure_fdpass_dropin("clamav-clamonacc")
    dropin = dropin_dir / unit.FDPASS_DROPIN_NAME
    assert dropin.is_file()
    assert "clamonacc -F --fdpass" in dropin.read_text(encoding="utf-8")


def test_restart_clam_stack_ensures_signatures_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    calls: list[str] = []

    def _ensure() -> str:
        calls.append("signatures")
        return "signatures present"

    def _sysctl(args: list[str]) -> None:
        calls.append(" ".join(args))

    monkeypatch.setattr(unit, "ensure_host_daily_signatures", _ensure)
    monkeypatch.setattr(unit, "_run_systemctl", _sysctl)
    monkeypatch.setattr(unit, "wait_for_clamd_ready", lambda **_k: None)
    monkeypatch.setattr(unit, "validate_unit", lambda u: u)
    unit.restart_clam_stack("clamav-daemon", None)
    assert calls[0] == "signatures"
    assert calls[1] == "restart clamav-daemon"


def test_ensure_fdpass_dropin_preflights_clamd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    dropin_dir = tmp_path / "clamav-clamonacc.service.d"
    real_path = Path
    calls: list[str] = []

    def _path(arg: object) -> Path:
        text = str(arg)
        if text.startswith("/etc/systemd/system/") and text.endswith(".service.d"):
            return dropin_dir
        return real_path(arg)

    def _enable(clamd: str | None, clamonacc: str | None, *, sockets=None) -> None:
        calls.append(f"enable:{clamd}:{clamonacc}")

    monkeypatch.setattr(unit, "Path", _path)
    monkeypatch.setattr(unit, "ensure_host_daily_signatures", lambda: "signatures present")
    monkeypatch.setattr(unit, "_unit_file_listed", lambda u: u == "clamav-daemon")
    monkeypatch.setattr(unit, "enable_clam_stack", _enable)
    monkeypatch.setattr(unit, "_systemctl_show", lambda *_a, **_k: "")
    monkeypatch.setattr(unit, "validate_unit", lambda u: u)
    monkeypatch.setattr(unit, "_resolve_clamonacc_bin", lambda: "/usr/bin/clamonacc")
    monkeypatch.setattr(unit, "_run_systemctl", lambda *_a, **_k: None)
    unit.ensure_fdpass_dropin("clamav-clamonacc")
    assert calls == ["enable:clamav-daemon:None"]
    assert (dropin_dir / unit.FDPASS_DROPIN_NAME).is_file()


def test_ensure_disable_cache_writes_harden_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\n", encoding="utf-8")
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    monkeypatch.setattr(mod, "restart_clam_stack", lambda *_a, **_k: None)
    _build_clamd_cocontrol_argv(["ensure-disable-cache", f"--conf={conf}"])
    text = conf.read_text(encoding="utf-8")
    assert "DisableCache yes" in text
    assert "# oysterAV Harden begin" in text


def test_ensure_disable_cache_handoff_foreign_no(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\nDisableCache no\n", encoding="utf-8")
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    with pytest.raises(ValueError, match="foreign DisableCache"):
        _build_clamd_cocontrol_argv(["ensure-disable-cache", f"--conf={conf}"])


def test_enable_clam_stack_ensures_signatures_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    calls: list[str] = []

    def _ensure() -> str:
        calls.append("signatures")
        return "freshclam updated signatures"

    def _sysctl(args: list[str]) -> None:
        calls.append(" ".join(args))

    monkeypatch.setattr(unit, "ensure_host_daily_signatures", _ensure)
    monkeypatch.setattr(unit, "_run_systemctl", _sysctl)
    monkeypatch.setattr(unit, "wait_for_clamd_ready", lambda **_k: None)
    monkeypatch.setattr(unit, "validate_unit", lambda u: u)
    unit.enable_clam_stack("clamav-daemon", None)
    assert calls[0] == "signatures"
    assert calls[1] == "enable --now clamav-daemon"


def test_ensure_host_daily_signatures_skips_when_present(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    daily = tmp_path / "daily.cvd"
    daily.write_text("x", encoding="utf-8")
    monkeypatch.setattr(unit, "_HOST_DAILY_SIGNATURES", (daily,))
    assert unit.ensure_host_daily_signatures() == "signatures present"
