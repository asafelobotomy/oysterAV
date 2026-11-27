"""LMD 2.x writes hits to session.tsv.<id> (no session.hits, no per-file {hit} lines)."""

from __future__ import annotations

from pathlib import Path

import pytest

# Captured from maldet 2.0.1 (Arch container, EICAR in a user-owned folder).
TSV = (
    "#LMD:v1\tscan\t261127-1103.358\tvm\t/home/u/scan\tall\tNov 27 2026 11:03:33 +0000\t"
    "Nov 27 2026 11:03:34 +0000\t1\t0\t1\t1\t0\t2.0.1\t2026112590478\tsha256\tnative\t0\t"
    "e586708402efc2242d6b5ea58b41f878\n"
    "{SHA256}test.test.eicar.29805\t/home/u/scan/eicar.com\t-\tSHA256\tSHA-256 Hash\t"
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\t68\tnobody\tnobody\t644\t"
    "1795777413\n"
)
CONSOLE = """maldet(358): {scan} scan of /home/u/scan (1 files) in progress...
maldet(358): {hit} 1 malware hits recorded [sha256]
maldet(358): {scan} scan completed on /home/u/scan: files 1, malware hits 1, cleaned hits 0, time 1s
maldet(358): {scan} scan report saved, to view run: maldet --report 261127-1103.358
"""


def _sess(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    from oyst_core.packs import maldet_parse

    sess = tmp_path / "pub" / "user" / "sess"
    sess.mkdir(parents=True)
    binary = tmp_path / "maldet"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(maldet_parse, "current_username", lambda: "user")
    monkeypatch.setattr(maldet_parse, "is_full_mode", lambda: False)
    return sess, binary


def test_tsv_session_is_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.packs import maldet_parse

    sess, binary = _sess(tmp_path, monkeypatch)
    (sess / "session.tsv.261127-1103.358").write_text(TSV, encoding="utf-8")
    scan_id = maldet_parse.scan_id_from_output(CONSOLE)
    assert scan_id == "261127-1103.358"
    findings = maldet_parse.load_session_hit_findings(str(binary), scan_id)
    assert [(f.path, f.threat_name) for f in findings] == [
        ("/home/u/scan/eicar.com", "{SHA256}test.test.eicar.29805")
    ]
    # The 2.x console summary line is not a per-file hit.
    assert maldet_parse.parse_console_output(CONSOLE) == []


def test_scan_id_beats_older_sessions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from oyst_core.packs import maldet_parse

    sess, binary = _sess(tmp_path, monkeypatch)
    (sess / "session.tsv.261127-1103.358").write_text(TSV, encoding="utf-8")
    clean = TSV.splitlines()[0] + "\n"
    (sess / "session.tsv.261127-1200.400").write_text(clean, encoding="utf-8")
    assert maldet_parse.load_session_hit_findings(str(binary), "261127-1200.400") == []
    assert len(maldet_parse.load_session_hit_findings(str(binary), "261127-1103.358")) == 1


def test_header_and_short_lines_are_skipped() -> None:
    from oyst_core.packs.maldet_parse import parse_session_tsv_text

    assert parse_session_tsv_text("#LMD:v1\tscan\n\nonlyonefield\nsig\trelative/path\n") == []


def test_abort_line_becomes_a_pack_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """LMD exits 0 after "aborting!" (no signatures); that must not read as a clean scan."""
    from oyst_core.models import PartialScanError
    from oyst_core.packs.maldet import MaldetPack
    from oyst_core.packs.maldet_parse import maldet_abort_reason

    line = (
        "maldet(158): {scan} required signature file not found (/x/sigs/md5v2.dat), "
        "try running -u|--update, aborting!"
    )
    assert maldet_abort_reason(line).startswith("required signature file not found")
    assert maldet_abort_reason(CONSOLE) == ""
    pack = MaldetPack()
    monkeypatch.setattr(pack, "scan", lambda path: (True, line))
    monkeypatch.setattr(pack, "parse_findings", lambda output: [])
    with pytest.raises(PartialScanError, match="required signature file"):
        pack.scan_paths(["/tmp"])
