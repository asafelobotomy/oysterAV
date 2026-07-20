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
    with pytest.raises(ValueError):
        _validate_include("/")
    with pytest.raises(ValueError):
        _validate_include("/etc")
    with pytest.raises(ValueError):
        _validate_include("/var/tmp")
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


def test_helper_ensure_virusevent_writes_markers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("User clamav\n", encoding="utf-8")
    # Helper validates /etc paths — monkeypatch validator by calling internals.
    from oyst_core.privileged import helper_clamd as mod

    monkeypatch.setattr(mod, "_validate_conf_path", lambda raw: Path(raw))
    monkeypatch.setattr(mod, "restart_clam_stack", lambda *_a, **_k: None)
    wrapper = "/home/u/.local/share/oysterav/bin/oyst-virusevent"
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


def test_wait_for_clamd_ready_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.privileged import helper_clamd_unit as unit

    monkeypatch.setattr(unit, "_WAIT_TIMEOUT_SEC", 0.2)
    monkeypatch.setattr(unit, "_WAIT_POLL_SEC", 0.05)
    monkeypatch.setattr(unit, "_socket_ready", lambda _extra=None: False)
    with pytest.raises(ValueError, match="socket not ready"):
        unit.wait_for_clamd_ready(timeout_sec=0.2)
