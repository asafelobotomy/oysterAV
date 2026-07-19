#!/usr/bin/env bash
# Local CLI smoke checks for internal production validation.
set -euo pipefail

cd "$(dirname "$0")/.."

run() {
  echo "+ $*"
  uv run oyst-cli "$@"
}

run doctor --json >/dev/null
run setup status --json >/dev/null
run setup check --json >/dev/null || true
run config get --json >/dev/null
run status --json >/dev/null
run status assess --json >/dev/null
run quarantine verify --json >/dev/null
run audit list --json >/dev/null
run packs list --json >/dev/null
run schedule status --json >/dev/null

echo "CLI smoke checks passed."
