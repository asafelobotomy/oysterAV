"""Regression tests for audit §3 Medium fixes (grant timer, scan reports, pacman, updates)."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oyst_core.privileged.runner import CommandResult

_JOB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# --- 1. grant expiry timer -------------------------------------------------


def test_expire_timer_uses_absolute_oncalendar(tmp_path: Path) -> None:
    from oyst_core.privileged.auth_grant_expire import install_expire_timer
    from oyst_core.privileged.auth_grant_scope import EXPIRE_TIMER_UNIT

    expires = datetime(2026, 10, 18, 12, 0, 0, tzinfo=UTC)
    install_expire_timer(prefix=tmp_path, expires=expires)
    timer = (tmp_path / "etc" / "systemd" / "system" / EXPIRE_TIMER_UNIT).read_text()
    assert "OnCalendar=2026-10-18 12:00:00 UTC" in timer
    assert "Persistent=true" in timer
    assert "OnActiveSec" not in timer


def test_grant_threads_stamp_expiry_into_timer(tmp_path: Path) -> None:
    from oyst_core.privileged.auth_grant import grant_service_lifecycle

    expires = datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)
    with patch("oyst_core.privileged.auth_grant.install_expire_timer") as timer:
        result = grant_service_lifecycle("alice", prefix=tmp_path, expires=expires)
    assert result["ok"] is True
    timer.assert_called_once_with(prefix=tmp_path, expires=expires)


# --- 2. scan-concert reports -----------------------------------------------


def test_scan_report_readable_by_caller_and_dirs_root_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_scan_concert as hsc

    root = tmp_path / "var" / "lib" / "oysterav" / "scan-reports"
    root.parent.parent.mkdir(parents=True)
    monkeypatch.setattr(hsc, "_REPORT_ROOT", root)
    monkeypatch.setattr(hsc, "_REPORT_DIR_OWNER", os.getuid())
    monkeypatch.setenv("PKEXEC_UID", str(os.getuid()))

    path = Path(hsc._write_report(_JOB, "rkhunter", "Warning: x\n"))
    assert path == root / _JOB / "rkhunter.out"
    assert path.read_text() == "Warning: x\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(root.stat().st_mode) & 0o001  # others may traverse
    assert stat.S_IMODE(root.parent.stat().st_mode) & 0o001
    assert stat.S_IMODE((root / _JOB).stat().st_mode) == 0o755  # not caller-writable


def test_scan_report_refuses_symlinked_job_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_scan_concert as hsc

    root = tmp_path / "oysterav" / "scan-reports"
    root.mkdir(parents=True)
    monkeypatch.setattr(hsc, "_REPORT_ROOT", root)
    monkeypatch.setattr(hsc, "_REPORT_DIR_OWNER", os.getuid())
    target = tmp_path / "elsewhere"
    target.mkdir()
    (root / _JOB).symlink_to(target)
    with pytest.raises(OSError):
        hsc._write_report(_JOB, "lynis", "x")
    assert not (target / "lynis.out").exists()


def test_scan_report_refuses_symlinked_report_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_scan_concert as hsc

    root = tmp_path / "oysterav" / "scan-reports"
    (root / _JOB).mkdir(parents=True)
    monkeypatch.setattr(hsc, "_REPORT_ROOT", root)
    monkeypatch.setattr(hsc, "_REPORT_DIR_OWNER", os.getuid())
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (root / _JOB / "lynis.out").symlink_to(victim)
    with pytest.raises(OSError):
        hsc._write_report(_JOB, "lynis", "x")
    assert victim.read_text() == "keep"


def test_scan_report_refuses_foreign_owned_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core.privileged import helper_scan_concert as hsc

    root = tmp_path / "oysterav" / "scan-reports"
    root.mkdir(parents=True)
    monkeypatch.setattr(hsc, "_REPORT_ROOT", root)
    monkeypatch.setattr(hsc, "_REPORT_DIR_OWNER", os.getuid() + 1)
    with pytest.raises(ValueError, match="root-owned"):
        hsc._write_report(_JOB, "lynis", "x")


# --- 3. no Arch partial upgrades --------------------------------------------


def test_pacman_argv_never_refreshes_sync_db() -> None:
    from oyst_core.privileged.helper import _build_install_argv
    from oyst_core.privileged.helper_fw_lifecycle import _family_install_argv as fw_argv
    from oyst_core.privileged.helper_setup_concert import _family_install_argv as setup_argv
    from oyst_core.privileged.helper_update_concert import _family_upgrade_argv

    argvs = [
        _build_install_argv(["clamav"], "arch", sync=True),
        setup_argv("arch", ["clamav"]),
        fw_argv("arch", ["ufw"]),
        _family_upgrade_argv("arch", ["clamav"]),
    ]
    for argv in argvs:
        assert argv is not None
        assert argv[1] == "-S"
        assert "-Sy" not in argv and "-Syu" not in argv


# --- 4. AUR upgrades need explicit consent ----------------------------------


def _aur_update() -> dict[str, object]:
    return {
        "ok": True,
        "updates": [
            {"kind": "pack", "name": "chkrootkit", "package": "chkrootkit", "current": "1"},
        ],
        "message": "",
    }


@pytest.mark.parametrize("confirm", [False, True])
def test_update_all_aur_requires_confirm(confirm: bool) -> None:
    from oyst_core.updates import apply_all_updates

    pack = MagicMock()
    pack.doctor.return_value.installed = False
    with (
        patch("oyst_core.updates.check_available_updates", return_value=_aur_update()),
        patch("oyst_core.updates.detect_distro_family", return_value="arch"),
        patch("oyst_core.updates.run_privilege_concert", return_value=[]),
        patch(
            "oyst_core.updates.run_privileged_aur_install",
            return_value=CommandResult(0, "ok", ""),
        ) as aur,
        patch("oyst_core.updates.FreshclamPack", return_value=pack),
        patch("oyst_core.updates.FangfrischPack", return_value=pack),
        patch("oyst_core.updates.RKHunterPack", return_value=pack),
        patch("oyst_core.updates.MaldetPack", return_value=pack),
        patch("oyst_core.updates.is_full_mode", return_value=False),
        patch("oyst_core.updates.EventLog"),
    ):
        result = apply_all_updates(confirm_aur=confirm)

    step = next(s for s in result["steps"] if s["step"] == "packages-aur")
    if confirm:
        aur.assert_called_once_with(["chkrootkit"])
        assert result["packages_upgraded"] == ["chkrootkit"]
    else:
        aur.assert_not_called()
        assert step["skipped"] is True
        assert "AUR helper" in step["message"]
        assert result["packages_upgraded"] == []
        assert result["ok"] is True


# --- 5. dnf .arch suffix -----------------------------------------------------


def test_dnf_check_update_strips_arch_suffix() -> None:
    from oyst_core import updates_query

    out = (
        "\nclamav.x86_64        1.4.3-1.fc42      updates\n"
        "python3-foo.noarch    2.0-1.fc42        updates\n"
    )
    with (
        patch.object(updates_query, "run_command", return_value=CommandResult(100, out, "")),
        patch.object(updates_query, "_rpm_installed_version", return_value="1.4.2-1.fc42"),
    ):
        rows = updates_query._query_dnf_upgrades()
    assert [r[0] for r in rows] == ["clamav", "python3-foo"]
    assert rows[0][2] == "1.4.3-1.fc42"


# --- 6. one malformed feed does not abort the rest ---------------------------


def test_malformed_feed_does_not_abort_other_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from oyst_core import security_news_fetch as snf
    from oyst_core.security_news_sources import NEWS_SOURCES

    good = (
        '<?xml version="1.0"?><rss version="2.0"><channel><item><title>USN-1-1: x</title>'
        "<link>https://ubuntu.com/security/notices/USN-1-1</link>"
        f"<pubDate>{datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>"
        "</item></channel></rss>"
    )

    def fake_fetch(url: str) -> str:
        return "<rss><unclosed" if url == NEWS_SOURCES["arch"].url else good

    monkeypatch.setattr(snf, "_fetch_url", fake_fetch)
    monkeypatch.setattr(snf, "_load_cache", lambda: None)
    monkeypatch.setattr(snf, "_save_cache", lambda _p: None)
    result = snf.fetch_security_news(sources=["arch", "ubuntu"], force=True, max_age_days=30)
    assert [e["source"] for e in result["errors"]] == [NEWS_SOURCES["arch"].label]
    assert result["items"]


# --- 7. fangfrisch hash-pinned install -------------------------------------


def test_fangfrisch_pip_install_is_hash_pinned() -> None:
    from oyst_core.runtime.bundles.fangfrisch_bundle import (
        FANGFRISCH_REQUIREMENTS,
        _pip_install_argv,
    )

    argv = _pip_install_argv(Path("/venv/bin/pip"))
    assert "--require-hashes" in argv and "--no-deps" in argv
    assert argv[argv.index("--only-binary") + 1] == ":all:"
    assert argv[argv.index("-r") + 1] == str(FANGFRISCH_REQUIREMENTS)
    text = FANGFRISCH_REQUIREMENTS.read_text(encoding="utf-8")
    assert "fangfrisch==1.9.2" in text
    pins = [ln for ln in text.splitlines() if ln and not ln[0].isspace() and ln[0] != "#"]
    assert pins and all("==" in ln and ln.endswith("\\") for ln in pins)
