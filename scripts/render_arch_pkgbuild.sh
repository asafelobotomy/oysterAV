#!/usr/bin/env bash
# Render packaging/arch/PKGBUILD from PKGBUILD.in using VERSION + archive sha256.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
REQUIRE_SHA256="${REQUIRE_SHA256:-0}"
ARCHIVE_URL="https://github.com/asafelobotomy/oysterAV/archive/refs/tags/v${VERSION}.tar.gz"
mkdir -p "$OUT_DIR" packaging/arch

resolve_sha256() {
  if [[ -n "${ARCHIVE_SHA256:-}" ]]; then
    printf '%s' "$ARCHIVE_SHA256"
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  if command -v curl >/dev/null 2>&1 && curl -fsSL "$ARCHIVE_URL" -o "$tmp"; then
    sha256sum "$tmp" | awk '{print $1}'
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  if [[ "$REQUIRE_SHA256" == "1" ]]; then
    echo "ERROR: could not download $ARCHIVE_URL to compute sha256sums" >&2
    exit 1
  fi
  echo "SKIP"
}

SHA256="$(resolve_sha256)"
sed -e "s/@VERSION@/${VERSION}/g" -e "s/@SHA256@/${SHA256}/g" \
  packaging/arch/PKGBUILD.in > packaging/arch/PKGBUILD
cp packaging/arch/PKGBUILD "$OUT_DIR/PKGBUILD"

# Full .SRCINFO for AUR tooling (no makepkg required).
cat >"$OUT_DIR/.SRCINFO" <<EOF
pkgbase = oysterav
pkgname = oysterav
pkgver = ${VERSION}
pkgrel = 1
pkgdesc = Linux security orchestrator: oyst-cli backend + oysterAV GTK4 GUI
url = https://github.com/asafelobotomy/oysterAV
arch = any
license = GPL-3.0-or-later
depends = python
depends = python-click
depends = python-pydantic
depends = python-defusedxml
depends = python-gobject
depends = gtk4
depends = libadwaita
depends = polkit
makedepends = python-build
makedepends = python-installer
makedepends = python-wheel
makedepends = python-hatchling
optdepends = clamav: required scanner spine
optdepends = rkhunter: rootkit checks
optdepends = chkrootkit: rootkit checks
optdepends = lynis: hardening audits
source = oysterav-${VERSION}.tar.gz::https://github.com/asafelobotomy/oysterAV/archive/refs/tags/v${VERSION}.tar.gz
sha256sums = ${SHA256}
EOF

cp "$OUT_DIR/.SRCINFO" packaging/arch/.SRCINFO

if [[ "$SHA256" == "SKIP" ]]; then
  echo "Wrote $OUT_DIR/PKGBUILD and $OUT_DIR/.SRCINFO (sha256sums=SKIP; tag archive unavailable)"
else
  echo "Wrote $OUT_DIR/PKGBUILD and $OUT_DIR/.SRCINFO (sha256=${SHA256})"
fi
