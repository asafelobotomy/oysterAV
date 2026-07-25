#!/usr/bin/env python3
"""Branch coverage gate for privilege / auth / firewall security modules.

Fails when covered lines on SECURITY_MODULES fall below FAIL_UNDER (default 85).
Runs a focused pytest set that exercises those modules (security suite + related
core tests) under the stdlib/coverage.py runner — separate from global fail_under.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAIL_UNDER = 85

SECURITY_MODULES = (
    "oyst_core/privileged/validators.py",
    "oyst_core/privileged/helper_firewall.py",
    "oyst_core/privileged/helper_fw_lifecycle.py",
    "oyst_core/privileged/helper_validate.py",
    "oyst_core/rpc_auth.py",
    "oyst_core/packs/firewall.py",
    "oyst_core/packs/firewall_ops.py",
    "oyst_core/packs/firewall_select.py",
    "oyst_core/packs/firewall_ensure.py",
    "oyst_core/audit.py",
)

# Tests that drive the security modules (marker suite + related core).
TEST_PATHS = (
    "tests/test_security",
    "tests/test_core/test_firewall_ops.py",
    "tests/test_core/test_oyst_helper.py",
    "tests/test_core/test_rpc_auth.py",
    "tests/test_core/test_audit_privacy.py",
    "tests/test_core/test_runner_allowlist.py",
)


def main() -> int:
    rcfile = ROOT / "scripts" / "security.coveragerc"
    cov_data = ROOT / ".coverage.security"
    if cov_data.is_file():
        cov_data.unlink()

    run_cmd = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        f"--rcfile={rcfile}",
        f"--data-file={cov_data}",
        "-m",
        "pytest",
        *TEST_PATHS,
        "-q",
        "--no-cov",
    ]
    print("==> security coverage (run)", flush=True)
    proc = subprocess.run(run_cmd, cwd=ROOT, check=False)
    if proc.returncode != 0:
        print("security coverage: pytest failed", file=sys.stderr)
        return proc.returncode

    report_cmd = [
        sys.executable,
        "-m",
        "coverage",
        "report",
        f"--rcfile={rcfile}",
        f"--data-file={cov_data}",
        f"--fail-under={FAIL_UNDER}",
        "--show-missing",
    ]
    print("==> security coverage (report)", flush=True)
    report = subprocess.run(report_cmd, cwd=ROOT, check=False)
    if report.returncode != 0:
        print(
            f"security coverage: below {FAIL_UNDER}% on SECURITY_MODULES",
            file=sys.stderr,
        )
        print("Modules:", ", ".join(SECURITY_MODULES), file=sys.stderr)
        return report.returncode
    print(f"OK: security module coverage ≥ {FAIL_UNDER}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
