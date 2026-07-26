#!/usr/bin/env bash
# Hostile-client simulation helpers for oysterAV (no privilege escalation payloads).
# See docs/security/attacker-sim.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
attacker_sim.sh — oysterAV hostile-client checks

Usage:
  scripts/attacker_sim.sh --help
  scripts/attacker_sim.sh --dry-run
  scripts/attacker_sim.sh --nightly

Modes:
  --help      Show this help (exit 0)
  --dry-run   Run in-repo security property tests that simulate hostile inputs
              (no live serve / no polkit). Exit 0 on success.
  --nightly   Same as dry-run plus pytest -m security_nightly (if any)
EOF
}

run_dry() {
  echo "attacker_sim: dry-run (pytest -m security, selected modules)"
  uv run pytest -m security -q --no-cov \
    tests/test_security/test_rpc_adversarial.py \
    tests/test_security/test_rpc_dos_bounds.py \
    tests/test_security/test_helper_env_argc.py \
    tests/test_security/test_helper_seal_install_adversarial.py \
    tests/test_security/test_helper_services_argv.py \
    tests/test_security/test_concert_abuse.py \
    tests/test_security/test_quarantine_refuse.py \
    tests/test_security/test_wave2_privilege.py \
    tests/test_security/test_eicar_detection_path.py
}

run_nightly() {
  run_dry
  echo "attacker_sim: nightly marker suite"
  uv run pytest -m security_nightly -q --no-cov || {
    # No nightly tests registered yet is OK
    code=$?
    if [[ "$code" -eq 5 ]]; then
      echo "attacker_sim: no security_nightly tests collected (ok)"
      return 0
    fi
    return "$code"
  }
}

case "${1:-}" in
  --help|-h|"")
    usage
    exit 0
    ;;
  --dry-run)
    run_dry
    ;;
  --nightly)
    run_nightly
    ;;
  *)
    echo "unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac
