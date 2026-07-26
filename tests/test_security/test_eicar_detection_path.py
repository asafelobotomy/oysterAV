"""EICAR detection-path smoke (mocked always; live opt-in via OYST_EICAR_LIVE=1)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from oyst_core.models import Finding
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.privileged.runner import CommandResult
from oyst_core.quarantine_guards import quarantine_refuse_reason

pytestmark = pytest.mark.security

# Standard EICAR test string (safe; not malware).
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_detection_path_mocked(tmp_path: Path) -> None:
    target = tmp_path / "eicar.com"
    target.write_text(EICAR, encoding="ascii")
    stdout = f"{target}: Eicar-Test-Signature FOUND\n----------- SCAN SUMMARY -----------\n"
    pack = ClamAVPack()
    with patch.object(
        pack,
        "scan",
        return_value=CommandResult(1, stdout, ""),
    ) as scan:
        findings = pack.scan_paths([str(target)], backend="clamscan")
    scan.assert_called_once()
    assert len(findings) >= 1
    hit = findings[0]
    assert isinstance(hit, Finding)
    assert str(target) in hit.path or hit.path.endswith("eicar.com")
    assert "Eicar" in hit.threat_name
    assert quarantine_refuse_reason(str(target)) is None


@pytest.mark.skipif(
    os.environ.get("OYST_EICAR_LIVE") != "1",
    reason="Set OYST_EICAR_LIVE=1 with host clamscan for live EICAR smoke",
)
def test_eicar_detection_path_live(tmp_path: Path) -> None:
    if shutil.which("clamscan") is None:
        pytest.skip("clamscan not on PATH")
    target = tmp_path / "eicar.com"
    target.write_text(EICAR, encoding="ascii")
    pack = ClamAVPack()
    findings = pack.scan_paths([str(target)], backend="clamscan")
    assert any("Eicar" in f.threat_name or "EICAR" in f.threat_name.upper() for f in findings)
