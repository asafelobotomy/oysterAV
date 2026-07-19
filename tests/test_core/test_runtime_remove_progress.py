"""Tests for runtime download progress and remove."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.config import OysterConfig, RuntimeConfig, save_config
from oyst_core.runtime.bootstrap import remove_pack_runtime
from oyst_core.runtime.download import download_file
from oyst_core.runtime.manifest import detect_arch, load_runtime_lock, record_artifact


class _FakeResponse:
    def __init__(self, data: bytes, *, content_length: bool = True) -> None:
        self._data = data
        self._offset = 0
        self.headers = {"Content-Length": str(len(data))} if content_length else {}

    def read(self, n: int = -1) -> bytes:
        if self._offset >= len(self._data):
            return b""
        if n < 0:
            chunk = self._data[self._offset :]
            self._offset = len(self._data)
            return chunk
        chunk = self._data[self._offset : self._offset + n]
        self._offset += len(chunk)
        return chunk

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_download_file_reports_increasing_percent(tmp_path: Path) -> None:
    dest = tmp_path / "blob.bin"
    payload = b"x" * (128 * 1024)
    seen: list[tuple[str, int]] = []

    def on_progress(stage: str, percent: int) -> None:
        seen.append((stage, percent))

    with patch(
        "oyst_core.runtime.download.urlopen",
        return_value=_FakeResponse(payload),
    ):
        import hashlib

        digest = hashlib.sha256(payload).hexdigest()
        download_file(
            "https://example.test/blob",
            dest,
            expected_sha256=digest,
            on_progress=on_progress,
        )

    assert dest.read_bytes() == payload
    download_events = [p for s, p in seen if s == "download"]
    assert download_events
    assert download_events[-1] == 100
    assert download_events == sorted(download_events)


def test_remove_pack_runtime_clears_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))

    arch = detect_arch()
    root = tmp_path / "runtime" / arch
    lynis_dir = root / "lynis"
    lynis_dir.mkdir(parents=True)
    lynis_bin = lynis_dir / "lynis"
    lynis_bin.write_text("#!/bin/sh\necho lynis\n", encoding="utf-8")
    lynis_bin.chmod(0o755)
    record_artifact("lynis", lynis_bin, source="test")

    events: list[int] = []
    result = remove_pack_runtime(
        "lynis",
        on_progress=lambda _s, p: events.append(p),
    )
    assert result["ok"] is True
    assert not lynis_dir.exists()
    lock = load_runtime_lock()
    assert all(a.name != "lynis" for a in lock.artifacts)
    assert events
    assert events[-1] == 100


def test_remove_pack_runtime_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_dir = tmp_path / "config" / "oysterav"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr("oyst_core.config.config_dir", lambda: cfg_dir)
    monkeypatch.setattr("oyst_core.config.config_path", lambda: cfg_dir / "config.toml")
    monkeypatch.setattr("oyst_core.runtime.manifest.data_dir", lambda: tmp_path)
    save_config(OysterConfig(runtime=RuntimeConfig(mode="full")))
    result = remove_pack_runtime("lynis")
    assert result["ok"] is False
    assert "No private runtime" in str(result["message"])


def test_runtime_remove_cli_help() -> None:
    from click.testing import CliRunner

    from oyst_cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["runtime", "remove", "--help"])
    assert result.exit_code == 0
    assert "private runtime" in result.output.lower() or "Remove" in result.output


def test_runtime_remove_cli_mocked() -> None:
    from click.testing import CliRunner

    from oyst_cli.main import cli

    runner = CliRunner()
    with patch(
        "oyst_cli.commands.runtime_cmd.remove_pack_runtime",
        return_value={"ok": True, "message": "Removed lynis", "removed": ["/tmp/lynis"]},
    ) as mocked:
        result = runner.invoke(cli, ["runtime", "remove", "lynis", "--confirm", "--json"])
    assert result.exit_code == 0
    mocked.assert_called_once()
    assert "Removed lynis" in result.output
