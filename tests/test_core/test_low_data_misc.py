"""Low-severity desktop/systemd quoting, redaction, and log-mode regressions."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import oyst_core.privileged  # noqa: F401  # import order: avoid schedule_linger cycle
from oyst_core import desktop_util
from oyst_core.audit import redact_paths
from oyst_core.schedule_linger import escape_systemd_exec_arg
from oyst_core.terminal_log import _strip_secrets


def _exec_line(entry: str) -> str:
    return next(line for line in entry.splitlines() if line.startswith("Exec="))[5:]


def test_flatpak_exec_is_separate_args(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(desktop_util, "is_flatpak", lambda: True)
    entry = desktop_util.build_desktop_entry(minimized=True)
    assert _exec_line(entry) == f"flatpak run {desktop_util.APP_ID} --minimized"


def test_exec_quotes_reserved_chars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(desktop_util, "resolve_oysterav_argv", lambda: ["/opt/my app/$x%1"])
    line = _exec_line(desktop_util.build_desktop_entry())
    # Arg-level: quoted, $ backslash-escaped, % doubled; string-level: \\ doubled.
    assert line == r'"/opt/my app/\\$x%%1"'


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/usr/bin/oyst-cli", "/usr/bin/oyst-cli"),
        ("/opt/$HOME/cli", "/opt/$$HOME/cli"),
        ("/opt/100%/cli", "/opt/100%%/cli"),
        ("/opt/a b/$x", '"/opt/a b/$$x"'),
    ],
)
def test_systemd_exec_escapes_dollar_and_percent(raw: str, expected: str) -> None:
    assert escape_systemd_exec_arg(raw) == expected


def test_systemd_exec_rejects_newline() -> None:
    with pytest.raises(ValueError):
        escape_systemd_exec_arg("/a\nb")


def test_strip_secrets_recurses_and_matches_key_substrings() -> None:
    data = {
        "API_Key": "k1",
        "apikey": "k2",
        "passphrase": "p",
        "client_secret": "s",
        "ssh_private_key": "pk",
        "Authorization": "Bearer x",
        "cookie": "c",
        "items": [{"password": "pw", "ok": 1}, ["x", {"token": "t"}]],
        "keep": "visible",
    }
    out = _strip_secrets(data)
    flat = repr(out)
    for secret in ("k1", "k2", "'p'", "'s'", "pk", "Bearer", "'c'", "pw", "'t'"):
        assert secret not in flat
    assert out["keep"] == "visible"
    assert out["items"][0]["ok"] == 1


def test_redact_paths_root_and_media() -> None:
    text = "/root/.ssh/id /run/media/bob/USB/a /media/carol/disk/b /home/dave/c"
    out = redact_paths(text)
    for name in (".ssh", "bob", "carol", "dave"):
        assert name not in out
    assert "/run/media/<redacted>/USB/a" in out
    assert "/media/<redacted>/disk/b" in out


def test_rotated_log_is_private(tmp_path: Path) -> None:
    from oyst_core.logging_util import PrivateRotatingFileHandler

    log_path = tmp_path / "oyst-cli.log"
    handler = PrivateRotatingFileHandler(log_path, maxBytes=50, backupCount=2)
    logger = logging.getLogger("oyst-test-rotate")
    logger.addHandler(handler)
    try:
        for i in range(10):
            logger.warning("line %d with padding to force rotation", i)
    finally:
        logger.removeHandler(handler)
        handler.close()
    assert (tmp_path / "oyst-cli.log.1").exists()
    for path in tmp_path.glob("oyst-cli.log*"):
        assert path.stat().st_mode & 0o777 == 0o600, path
