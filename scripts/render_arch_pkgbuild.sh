#!/usr/bin/env bash
# Render packaging/arch/PKGBUILD from PKGBUILD.in using VERSION.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT_DIR" packaging/arch

sed "s/@VERSION@/${VERSION}/g" packaging/arch/PKGBUILD.in > packaging/arch/PKGBUILD
cp packaging/arch/PKGBUILD "$OUT_DIR/PKGBUILD"

# Minimal .SRCINFO for AUR tooling (no makepkg required).
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
depends = python-gobject
depends = gtk4
depends = libadwaita
depends = polkit
source = oysterav-${VERSION}.tar.gz::https://github.com/asafelobotomy/oysterAV/archive/refs/tags/v${VERSION}.tar.gz
sha256sums = SKIP
EOF

echo "Wrote $OUT_DIR/PKGBUILD and $OUT_DIR/.SRCINFO"
