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

# .SRCINFO from the PKGBUILD itself (makepkg), so the two can't drift: a hand-written copy
# here once listed clamav as optional while the PKGBUILD depends on it. makepkg refuses to run
# as root, so as root (the release job's Arch container) it runs as a throwaway user.
srcinfo() {
  local dir
  dir="$(mktemp -d)"
  cp packaging/arch/PKGBUILD "$dir/PKGBUILD"
  if [[ "$(id -u)" == "0" ]]; then
    id -u builder >/dev/null 2>&1 || useradd -m builder
    chown -R builder "$dir"
    su builder -c "cd '$dir' && makepkg --printsrcinfo"
  else
    (cd "$dir" && makepkg --printsrcinfo)
  fi
  rm -rf "$dir"
}
if command -v makepkg >/dev/null 2>&1; then
  srcinfo >"$OUT_DIR/.SRCINFO"
  grep -qx "	pkgver = ${VERSION}" "$OUT_DIR/.SRCINFO"
  cp "$OUT_DIR/.SRCINFO" packaging/arch/.SRCINFO
elif [[ "$REQUIRE_SHA256" == "1" ]]; then
  echo "ERROR: makepkg is needed to write .SRCINFO (run this on Arch)" >&2
  exit 1
else
  echo "makepkg not found: .SRCINFO not written (run this on Arch for the AUR files)" >&2
  rm -f "$OUT_DIR/.SRCINFO"
fi

if [[ "$SHA256" == "SKIP" ]]; then
  echo "Wrote $OUT_DIR/PKGBUILD and $OUT_DIR/.SRCINFO (sha256sums=SKIP; tag archive unavailable)"
else
  echo "Wrote $OUT_DIR/PKGBUILD and $OUT_DIR/.SRCINFO (sha256=${SHA256})"
fi
