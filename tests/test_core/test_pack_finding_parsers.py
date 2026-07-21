"""Parser regression tests for rkhunter / chkrootkit / maldet false positives."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.packs.chkrootkit import ChkrootkitPack
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.privileged.runner import CommandResult


def test_rkhunter_requires_warning_prefix_and_classifies() -> None:
    output = """
Warning: Checking for prerequisites               [ Warning ]
grep: warning: stray \\ before -
egrep: warning: egrep is obsolescent; using grep -E
fgrep: warning: fgrep is obsolescent; using grep -F
Warning: The command '/usr/bin/egrep' has been replaced by a script: /usr/bin/egrep
Warning: The SSH configuration option 'PermitRootLogin' has not been set.
Warning: Hidden file found: /etc/.updated: ASCII text
Warning: WARNING! It is the users responsibility to ensure that when the '--propupd' option
Warning: Possible rootkit: something_suspicious
"""
    findings = RKHunterPack().parse_findings(output)
    by_threat = {f.threat_name: f for f in findings}
    assert "rkhunter-script-replacement" in by_threat
    assert by_threat["rkhunter-script-replacement"].severity.value == "low"
    assert by_threat["rkhunter-script-replacement"].path == "/usr/bin/egrep"
    assert "rkhunter-ssh" in by_threat
    assert by_threat["rkhunter-ssh"].severity.value == "low"
    assert "rkhunter-hidden" in by_threat
    assert by_threat["rkhunter-hidden"].path == "/etc/.updated"
    assert by_threat["rkhunter-hidden"].severity.value == "low"
    assert "rkhunter-advisory" in by_threat
    assert by_threat["rkhunter-advisory"].severity.value == "info"
    assert "rkhunter-rootkit" in by_threat
    assert by_threat["rkhunter-rootkit"].severity.value == "high"
    assert all(not f.message.lower().startswith("grep: warning:") for f in findings)
    assert all(not f.message.lower().startswith("egrep: warning:") for f in findings)
    assert all("prerequisites" not in f.message.lower() for f in findings)
    assert len(findings) == 5


def test_rkhunter_scan_uses_stdout_only_for_parse_input() -> None:
    pack = RKHunterPack()
    result = CommandResult(
        returncode=0,
        stdout=(
            "Warning: Hidden file found: /etc/.updated: ASCII text\n"
            "Warning: The SSH configuration option 'Protocol' has not been set.\n"
        ),
        stderr="egrep: warning: egrep is obsolescent; using grep -E\n" * 50,
    )
    with (
        patch(
            "oyst_core.packs.rkhunter.resolve_pack_binary",
            return_value=("/usr/bin/rkhunter", "system"),
        ),
        patch("oyst_core.packs.rkhunter.run_privileged_scanner", return_value=result),
    ):
        ok, output = pack.scan()
    assert ok
    assert "egrep: warning:" not in output
    assert output.count("Warning:") == 2
    findings = pack.parse_findings(output)
    assert len(findings) == 2


def test_rkhunter_scan_falls_back_to_stderr_when_stdout_empty_on_failure() -> None:
    pack = RKHunterPack()
    result = CommandResult(returncode=1, stdout="", stderr="rkhunter lock held\n")
    with (
        patch(
            "oyst_core.packs.rkhunter.resolve_pack_binary",
            return_value=("/usr/bin/rkhunter", "system"),
        ),
        patch("oyst_core.packs.rkhunter.run_privileged_scanner", return_value=result),
    ):
        ok, output = pack.scan()
    assert not ok
    assert "lock held" in output


def test_chkrootkit_drops_clean_negatives() -> None:
    output = """
Checking `basename'... not infected
Checking `chfn'... not infected
Checking `aliens'... no suspect files
Searching for suspect PHP files... nothing found
Checking `bindshell'... INFECTED
possible rootkit: suckit
"""
    findings = ChkrootkitPack().parse_findings(output)
    assert len(findings) == 2
    messages = " ".join(f.message for f in findings).lower()
    assert "infected" in messages or "rootkit" in messages
    assert all("not infected" not in f.message.lower() for f in findings)
    assert all("no suspect" not in f.message.lower() for f in findings)


def test_maldet_drops_version_banner_requires_path() -> None:
    output = """
Linux Malware Detect v1.6.6
maldet(123): {hit} malware hit {CAV}Eicar-Test-Signature found for /tmp/eicar.com
maldet: scan completed, 0 hits
"""
    findings = MaldetPack().parse_findings(output)
    assert len(findings) == 1
    assert findings[0].path == "/tmp/eicar.com"
    assert findings[0].threat_name == "{CAV}Eicar-Test-Signature"
    assert "/tmp/eicar.com" in findings[0].message


def test_maldet_rejects_scan_summary_and_clamav_binary_lines() -> None:
    output = """
maldet(1): {scan} found clamav binary at /usr/bin/clamdscan
maldet(1): {scan} scan completed on /home/solon64: files 100, malware hits 1
"""
    assert MaldetPack().parse_findings(output) == []


def test_maldet_session_hits_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.packs import maldet_parse

    pub = tmp_path / "pub" / "user"
    sess = pub / "sess"
    sess.mkdir(parents=True)
    (sess / "session.last").write_text("abc123", encoding="utf-8")
    hits = sess / "session.hits.abc123"
    hits.write_text(
        "{CAV}Html.Downloader.Satan-6249582-1 : /tmp/payload.bin\n",
        encoding="utf-8",
    )
    binary = tmp_path / "maldet"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(maldet_parse, "current_username", lambda: "user")
    monkeypatch.setattr(maldet_parse, "is_full_mode", lambda: False)
    findings = maldet_parse.load_session_hit_findings(str(binary))
    assert len(findings) == 1
    assert findings[0].path == "/tmp/payload.bin"
    assert findings[0].threat_name == "{CAV}Html.Downloader.Satan-6249582-1"


def test_maldet_filters_self_signature_path() -> None:
    from oyst_core.models import Finding, FindingSeverity
    from oyst_core.packs.maldet_parse import filter_malware_findings

    findings = [
        Finding(
            pack="maldet",
            path="/home/u/.local/share/oysterav/runtime/x86_64/maldetect/sigs/rfxn.yara",
            threat_name="{CAV}Html.Downloader",
            severity=FindingSeverity.HIGH,
            message="hit",
        ),
        Finding(
            pack="maldet",
            path="/tmp/evil.bin",
            threat_name="{CAV}Evil",
            severity=FindingSeverity.HIGH,
            message="hit",
        ),
    ]
    kept = filter_malware_findings(findings)
    assert len(kept) == 1
    assert kept[0].path == "/tmp/evil.bin"


def test_clamav_sets_message_from_found_line() -> None:
    result = CommandResult(
        returncode=1,
        stdout="/tmp/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n",
        stderr="",
    )
    findings = ClamAVPack().parse_findings(result)
    assert len(findings) == 1
    assert findings[0].path == "/tmp/eicar.com"
    assert "FOUND" in findings[0].message
    assert findings[0].threat_name == "Win.Test.EICAR_HDB-1"
