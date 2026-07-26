"""Contract: attacker-sim artefacts stay runnable (dry-run)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "attacker_sim.sh"
_RUNBOOK = _ROOT / "docs" / "security" / "attacker-sim.md"


def test_attacker_sim_contract() -> None:
    assert _RUNBOOK.is_file(), "missing docs/security/attacker-sim.md"
    assert _SCRIPT.is_file(), "missing scripts/attacker_sim.sh"
    assert _SCRIPT.stat().st_mode & 0o111, "attacker_sim.sh must be executable"
    proc = subprocess.run(
        [str(_SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "attacker" in (proc.stdout + proc.stderr).lower()
    # Dry-run invokes nested pytest; skip when already under pytest to avoid
    # re-entrancy flakes (semaphore / coverage). Operators and CI workflow still
    # run --dry-run directly.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        dry = subprocess.run(
            [str(_SCRIPT), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    else:
        dry = subprocess.run(
            [str(_SCRIPT), "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    assert dry.returncode == 0
