#!/usr/bin/env bash
# Local validation loop matching CI (see .github/workflows/ci.yml).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

SCOPE_RUFF=(oyst_core oyst_cli oysterav tests)
SCOPE_MYPY=(oyst_core oyst_cli oysterav)

usage() {
  cat <<'EOF'
Usage: scripts/check.sh [--quick] [--pytest-args ...]

  --quick   Skip coverage and run a faster pytest subset (tests/test_core tests/test_cli)
  --format  Also run ruff format --check

Gates (in order): version sync, 400-line LOC hard limit (ratchet), ruff, mypy,
pytest, security marker suite, security-module coverage (≥85%), Bandit, pip-audit.

See docs/security/test-gates.md for ASVS-oriented mapping.

Environment:
  Prefer: uv sync --extra all   (or --extra dev; add --extra gui for full GUI tests)

Health/debug (not part of this script):
  uv run oyst-cli doctor --json
  uv run oyst-cli status assess --json
  uv run oyst-cli serve --foreground
EOF
}

QUICK=0
FORMAT=0
PYTEST_EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --quick)
      QUICK=1
      shift
      ;;
    --format)
      FORMAT=1
      shift
      ;;
    --)
      shift
      PYTEST_EXTRA+=("$@")
      break
      ;;
    *)
      PYTEST_EXTRA+=("$1")
      shift
      ;;
  esac
done

echo "==> version sync"
uv run python scripts/sync_version.py --check

echo "==> LOC hard limit (400)"
uv run python scripts/check_loc.py

echo "==> ruff check"
uv run ruff check "${SCOPE_RUFF[@]}"

if [[ "${FORMAT}" -eq 1 ]]; then
  echo "==> ruff format --check"
  uv run ruff format --check "${SCOPE_RUFF[@]}"
fi

echo "==> mypy"
uv run mypy "${SCOPE_MYPY[@]}"

if [[ "${QUICK}" -eq 1 ]]; then
  echo "==> pytest (quick)"
  uv run pytest tests/test_core tests/test_cli tests/test_security --no-cov "${PYTEST_EXTRA[@]}"
else
  echo "==> pytest (with coverage)"
  uv run pytest tests/ --cov=oyst_core --cov=oyst_cli --cov-report=term-missing "${PYTEST_EXTRA[@]}"
fi

echo "==> pytest security marker"
uv run pytest -m security -q --no-cov

echo "==> security module coverage (≥85%)"
uv run python scripts/check_security_coverage.py

echo "==> bandit (medium+)"
uv tool run bandit -c bandit.yaml -r oyst_core oyst_cli -ll -ii

echo "==> pip-audit"
uv tool run pip-audit

echo "OK: check.sh passed"
