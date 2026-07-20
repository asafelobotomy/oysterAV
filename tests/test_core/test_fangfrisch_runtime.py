"""Fangfrisch private-runtime install helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.config import OysterConfig, RuntimeConfig, save_config
from oyst_core.runtime.manifest import detect_arch, runtime_bin_dir, runtime_root


def _isolate_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    monkeypatch.setattr("oyst_core.config.data_dir", lambda: tmp_path)
    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))


def test_install_fangfrisch_runtime_creates_venv_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_runtime(tmp_path, monkeypatch)

    dest_root = tmp_path / "runtime" / detect_arch() / "fangfrisch"
    venv_bin = dest_root / "bin" / "fangfrisch"
    pip = dest_root / "bin" / "pip"

    def fake_run(argv: list[str], **_kwargs: object) -> object:
        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        if "-m" in argv and "venv" in argv:
            (dest_root / "bin").mkdir(parents=True)
            pip.write_text("#!/bin/sh\n", encoding="utf-8")
            pip.chmod(0o755)
            return Result()
        if "fangfrisch" in argv:
            venv_bin.write_text("#!/bin/sh\necho fangfrisch\n", encoding="utf-8")
            venv_bin.chmod(0o755)
            return Result()
        return Result()

    with (
        patch("oyst_core.runtime.bundles.fangfrisch_bundle.subprocess.run", side_effect=fake_run),
        patch("oyst_core.runtime.bootstrap._configure_fangfrisch_after_install"),
        patch("oyst_core.packs.fangfrisch.FangfrischPack.ensure_config", return_value=(True, "ok")),
        patch("oyst_core.packs.fangfrisch.FangfrischPack.initdb", return_value=(True, "ok")),
    ):
        from oyst_core.runtime.bootstrap import install_pack_runtime

        result = install_pack_runtime("fangfrisch")

    assert result["ok"] is True
    assert venv_bin.is_file()
    link = runtime_bin_dir() / "fangfrisch"
    assert link.is_symlink() or link.is_file()
    assert runtime_root().joinpath("fangfrisch").is_dir()


def test_run_aur_install_does_not_use_pkexec() -> None:
    from oyst_core.privileged.helper import run_aur_install
    from oyst_core.privileged.runner import CommandResult

    with (
        patch("oyst_core.privileged.helper.detect_aur_helper", return_value="/usr/bin/paru"),
        patch(
            "oyst_core.privileged.helper.run_install_command",
            return_value=CommandResult(0, "ok", ""),
        ) as install_cmd,
        patch("oyst_core.privileged.helper.run_privileged") as privileged,
    ):
        result = run_aur_install(["python-fangfrisch"])
    privileged.assert_not_called()
    install_cmd.assert_called_once()
    argv = install_cmd.call_args.args[0]
    assert argv[0] == "/usr/bin/paru"
    assert "pkexec" not in argv
    assert result.returncode == 0
