#!/usr/bin/env bash
# Install-test built .deb/.rpm in clean distro containers and exercise the
# installed entry points (CLI, GUI import, root helper import + usage).
#
# Usage: scripts/smoke_native_packages.sh <dist-dir> [deb-image...] [-- rpm-image...]
# Defaults: debian:trixie ubuntu:26.04 -- fedora:latest
# (Ubuntu 24.04 is unsupported: it ships pydantic 1.x; oysterAV needs pydantic 2.)
# Container engine: $CONTAINER_ENGINE, else podman, else docker.
set -euo pipefail

DIST="$(cd "${1:?dist dir required}" && pwd)"
shift || true

DEB_IMAGES=()
RPM_IMAGES=()
target=deb
for arg in "$@"; do
  if [[ "$arg" == "--" ]]; then
    target=rpm
    continue
  fi
  if [[ "$target" == deb ]]; then DEB_IMAGES+=("$arg"); else RPM_IMAGES+=("$arg"); fi
done
[[ ${#DEB_IMAGES[@]} -eq 0 ]] && DEB_IMAGES=(docker.io/library/debian:trixie docker.io/library/ubuntu:26.04)
[[ ${#RPM_IMAGES[@]} -eq 0 ]] && RPM_IMAGES=(registry.fedoraproject.org/fedora:latest)

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman; else ENGINE=docker; fi
fi

DEB="$(ls "$DIST"/oysterav_*_all.deb)"
RPM="$(ls "$DIST"/oysterav-*.noarch.rpm)"

# Checks shared by both families; run inside the container after install.
read -r -d '' CHECKS <<'SH' || true
set -euo pipefail
echo "--- files"
test -x /usr/bin/oyst-cli
test -x /usr/bin/oysterav
test -x /usr/lib/oysterav/oyst-helper
test -f /usr/share/polkit-1/actions/io.github.asafelobotomy.policy
head -1 /usr/bin/oyst-cli | grep -qx '#!/usr/bin/python3 -I'
if find /usr/lib/oysterav/python -perm /022 | grep -q .; then
  echo "group/world-writable files under the private prefix" >&2; exit 1
fi
if find /usr/lib/oysterav/python -not -user root | grep -q .; then
  echo "non-root-owned files under the private prefix" >&2; exit 1
fi
echo "--- no bundled third-party deps"
for mod in click pydantic defusedxml; do
  test ! -e "/usr/lib/oysterav/python/$mod" || { echo "bundled $mod" >&2; exit 1; }
done
echo "--- CLI"
oyst-cli version
oyst-cli --help >/dev/null
echo "--- GUI module import (no display)"
python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/oysterav/python"); import gi; gi.require_version("Gtk", "4.0"); gi.require_version("Adw", "1"); import oysterav.main'
echo "--- helper"
python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/oysterav/python"); import oyst_core.privileged.oyst_helper'
set +e
out="$(/usr/lib/oysterav/oyst-helper 2>&1)"; rc=$?
set -e
echo "$out"
[[ $rc -eq 2 ]] && grep -q "usage: oyst-helper" <<<"$out"
echo "--- helper site trust"
python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/oysterav/python"); from oyst_core.privileged.helper_site_trust import untrusted_site_reason; from pathlib import Path; r = untrusted_site_reason(Path("/usr/lib/oysterav/python")); print(r or "trusted"); raise SystemExit(1 if r else 0)'
echo "OK"
SH

run_in() {
  local image="$1" install="$2" pkg="$3"
  echo "=== $image"
  "$ENGINE" run --rm -v "$DIST:/dist:ro,Z" "$image" \
    bash -c "set -euo pipefail; $install /dist/$(basename "$pkg")
$CHECKS"
}

status=0
for image in "${DEB_IMAGES[@]}"; do
  run_in "$image" \
    "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq" \
    "$DEB" || { echo "FAILED: $image" >&2; status=1; }
done
for image in "${RPM_IMAGES[@]}"; do
  run_in "$image" "dnf install -y -q" "$RPM" || { echo "FAILED: $image" >&2; status=1; }
done
exit "$status"
