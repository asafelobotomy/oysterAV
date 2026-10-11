"""ClamAV remediation (2026-10-11): clamd argv, version advisory, cancellable scans."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.models import PartialScanError
from oyst_core.packs import clamd_client
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamav_version import security_advisory
from oyst_core.packs.clamd_client import (
    ClamdEndpoint,
    clamdscan_argv,
    discover_endpoint,
    parse_socket_keys,
)
from oyst_core.privileged import runner
from oyst_core.privileged.runner import (
    CommandResult,
    parse_version,
    run_command_cancellable,
    version_gte,
)

# --- version parsing / advisory ------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.5.4", (1, 5, 4)),
        ("ClamAV 1.5.4-1", (1, 5, 4)),
        ("0.58", (0, 58)),
        ("v2_0", (2, 0)),
        ("none", (0,)),
    ],
)
def test_parse_version_reads_full_dotted_number(text: str, expected: tuple[int, ...]) -> None:
    assert parse_version(text) == expected


def test_version_gte_compares_minor_and_patch() -> None:
    assert not version_gte("1.3.0", "1.4.0")
    assert not version_gte("1.5.2", "1.5.4")
    assert version_gte("1.5.4", "1.5.4")
    assert version_gte("1.5", "1.5.0")
    assert version_gte("1.6.0", "1.5.4")


@pytest.mark.parametrize(
    ("version", "advised"),
    [
        ("1.4.5", True),
        ("1.4.6", False),
        ("1.5.3", True),
        ("1.5.4", False),
        ("1.6.0", False),
        (None, False),
    ],
)
def test_security_advisory_matrix(version: str | None, advised: bool) -> None:
    assert (security_advisory(version) is not None) is advised


# --- clamd endpoint / argv -----------------------------------------------------


def test_parse_socket_keys_strips_inline_comments() -> None:
    text = "LocalSocket /run/clamav/clamd.ctl # 1.5 inline comment\n#TCPSocket 3310\n"
    assert parse_socket_keys(text) == ("/run/clamav/clamd.ctl", False)
    assert parse_socket_keys("TCPSocket 3310\nTCPAddr 127.0.0.1\n") == (None, True)


def test_discover_endpoint_prefers_host_conf(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    conf.write_text("LocalSocket /run/clamd.scan/clamd.sock\n", encoding="utf-8")
    with patch.object(clamd_client, "discover_clamd_conf_paths", return_value=[conf]):
        ep = discover_endpoint()
    assert ep == ClamdEndpoint(conf=conf, local_socket="/run/clamd.scan/clamd.sock")


def test_fedora_socket_in_probe_list() -> None:
    assert "/run/clamd.scan/clamd.sock" in clamd_client.CLAMD_SOCKETS


def test_clamdscan_argv_unix_socket_uses_host_conf_and_fdpass(tmp_path: Path) -> None:
    conf = tmp_path / "clamd.conf"
    ep = ClamdEndpoint(conf=conf, local_socket="/run/clamav/clamd.ctl")
    argv = clamdscan_argv("/usr/bin/clamdscan", "/home/u/Downloads", endpoint=ep)
    assert argv == [
        "/usr/bin/clamdscan",
        f"--config-file={conf}",
        "--stdout",
        "--fdpass",
        "/home/u/Downloads",
    ]
    assert "--config-file=/dev/null" not in argv
    assert "-r" not in argv
    assert not any(a.startswith("--database") for a in argv)


def test_clamdscan_argv_tcp_has_no_fdpass_and_multiscan(tmp_path: Path) -> None:
    ep = ClamdEndpoint(conf=tmp_path / "c.conf", tcp=True)
    argv = clamdscan_argv("clamdscan", "/srv", multiscan=True, endpoint=ep)
    assert "--fdpass" not in argv
    assert "--multiscan" in argv


def test_clamdscan_argv_without_endpoint_raises() -> None:
    with pytest.raises(FileNotFoundError):
        clamdscan_argv("clamdscan", "/x", endpoint=ClamdEndpoint())


def test_private_conf_is_0600_with_socket_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(clamd_client, "data_dir", lambda: tmp_path)
    ep = ClamdEndpoint(local_socket="/run/clamav/clamd.ctl")
    argv = clamdscan_argv("clamdscan", "/x", endpoint=ep)
    conf = tmp_path / clamd_client.CLIENT_CONF_NAME
    assert argv[1] == f"--config-file={conf}"
    assert conf.read_text(encoding="utf-8") == "LocalSocket /run/clamav/clamd.ctl\n"
    assert stat.S_IMODE(conf.stat().st_mode) == 0o600


def test_private_conf_rejects_newline_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(clamd_client, "data_dir", lambda: tmp_path)
    with pytest.raises(ValueError):
        clamdscan_argv("clamdscan", "/x", endpoint=ClamdEndpoint(local_socket="/s\nUser root"))


# --- backend selection -----------------------------------------------------------


def test_auto_backend_full_mode_keeps_private_signatures() -> None:
    pack = ClamAVPack()
    with (
        patch("oyst_core.packs.clamav.is_full_mode", return_value=True),
        patch.object(pack, "clamd_running", return_value=True),
    ):
        assert pack.resolve_backend("auto") == "clamscan"
        assert pack.resolve_backend("clamd") == "clamd"


@pytest.mark.parametrize(("ping", "expected"), [(True, "clamd"), (False, "clamscan")])
def test_auto_backend_lite_requires_ping(ping: bool, expected: str) -> None:
    pack = ClamAVPack()
    with (
        patch("oyst_core.packs.clamav.is_full_mode", return_value=False),
        patch.object(pack, "clamd_running", return_value=True),
        patch(
            "oyst_core.packs.clamav.resolve_pack_binary",
            return_value=("/usr/bin/clamdscan", "system"),
        ),
        patch("oyst_core.packs.clamav.clamd_ping", return_value=ping),
    ):
        assert pack.resolve_backend("auto") == expected


# --- scan / scan_paths -----------------------------------------------------------


def _run_scan(pack: ClamAVPack, result: CommandResult, **kwargs: object) -> list[object]:
    with (
        patch.object(pack, "ensure_ignore_sigs"),
        patch(
            "oyst_core.packs.clamav.resolve_pack_binary",
            return_value=("/usr/bin/clamdscan", "system"),
        ),
        patch(
            "oyst_core.packs.clamav.clamdscan_argv",
            return_value=["/usr/bin/clamdscan", "--stdout", "/home/u"],
        ) as argv_mock,
        patch("oyst_core.packs.clamav.run_command_cancellable", return_value=result) as run_mock,
        patch(
            "oyst_core.packs.clamav.merged_clamav_exclude_dirs",
            return_value=["/home/u/.local/share/oysterav/quarantine"],
        ),
    ):
        findings = pack.scan_paths(["/home/u"], backend="clamd", profile="full", **kwargs)
    assert argv_mock.call_args.kwargs["multiscan"] is True
    assert run_mock.call_args.args[0][0] == "/usr/bin/clamdscan"
    return list(findings)


def test_clamd_scan_filters_findings_under_excluded_dirs() -> None:
    stdout = (
        "/home/u/.local/share/oysterav/quarantine/x.bin: Eicar FOUND\n"
        "/home/u/Downloads/eicar.com: Eicar FOUND\n"
    )
    findings = _run_scan(ClamAVPack(), CommandResult(1, stdout, ""))
    assert [f.path for f in findings] == ["/home/u/Downloads/eicar.com"]  # type: ignore[attr-defined]


def test_clamd_scan_error_detail_falls_back_to_stdout() -> None:
    out = "ERROR: Could not connect to clamd on LocalSocket /run/clamav/clamd.ctl\n"
    with pytest.raises(PartialScanError, match="Could not connect"):
        _run_scan(ClamAVPack(), CommandResult(2, out, ""))


def test_cancelled_scan_keeps_partial_findings() -> None:
    res = CommandResult(-15, "/home/u/a: Eicar FOUND\n", "", stopped="cancel")
    with pytest.raises(PartialScanError) as exc:
        _run_scan(ClamAVPack(), res, should_cancel=lambda: True)
    assert [f.path for f in exc.value.findings] == ["/home/u/a"]


def test_timed_out_scan_reports_partial_error() -> None:
    res = CommandResult(-15, "/home/u/a: Eicar FOUND\n", "", stopped="timeout")
    with pytest.raises(PartialScanError, match="timed out") as exc:
        _run_scan(ClamAVPack(), res)
    assert len(exc.value.findings) == 1


# --- run_command_cancellable -------------------------------------------------------


@pytest.fixture
def allow_python(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(runner, "ALLOWED_COMMANDS", frozenset({Path(sys.executable).name}))
    return sys.executable


def test_cancellable_returns_normally(allow_python: str) -> None:
    res = run_command_cancellable([allow_python, "-c", "print('ok')"], timeout=30)
    assert (res.returncode, res.stdout.strip(), res.stopped) == (0, "ok", None)


def test_cancellable_cancel_keeps_output(allow_python: str) -> None:
    code = "import sys,time; print('first', flush=True); time.sleep(60)"
    calls = {"n": 0}

    def should_cancel() -> bool:
        calls["n"] += 1
        return calls["n"] >= 2

    res = run_command_cancellable(
        [allow_python, "-c", code], timeout=60, should_cancel=should_cancel, poll=0.2
    )
    assert res.stopped == "cancel"
    assert "first" in res.stdout


def test_cancellable_timeout_escalates_to_kill(allow_python: str) -> None:
    code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    res = run_command_cancellable([allow_python, "-c", code], timeout=1, poll=0.2, grace=0.5)
    assert res.stopped == "timeout"
    assert res.returncode == -9


def test_cancellable_enforces_allowlist() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        run_command_cancellable(["/bin/definitely-not-allowed"], timeout=1)


# --- lite-mode ignore list ---------------------------------------------------------


def test_ignore_sigs_unwritable_db_dir_does_not_fail(tmp_path: Path) -> None:
    from oyst_core.config import OysterConfig

    locked = tmp_path / "clamav"
    locked.mkdir()
    locked.chmod(0o555)
    cfg = OysterConfig()
    cfg.clamav.ignore_sigs = ["Sanesecurity.Spam.1"]
    pack = ClamAVPack()
    try:
        with (
            patch("oyst_core.packs.clamav.load_config", return_value=cfg),
            patch.object(pack, "ignore_sigs_path", return_value=locked / "oysterav.ign2"),
        ):
            assert pack.ensure_ignore_sigs() is None
            assert pack.ignore_sigs_blocked() is (os.geteuid() != 0)
    finally:
        locked.chmod(0o755)
