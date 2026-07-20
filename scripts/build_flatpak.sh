#!/usr/bin/env bash
# Build a Flatpak bundle for oysterAV (local or CI).
# Network share is required so pip can fetch hatchling/build deps inside the SDK.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
ARCH="${1:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
esac

MANIFEST="packaging/oysterav/flatpak/io.github.asafelobotomy.OysterAV.yml"
APP_ID="io.github.asafelobotomy.OysterAV"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
BUNDLE="${OUT_DIR}/oysterAV-${VERSION}-${ARCH}.flatpak"
BUILD_DIR="${FLATPAK_BUILD_DIR:-$ROOT/build-dir}"
REPO_DIR="${FLATPAK_REPO_DIR:-$ROOT/repo}"

mkdir -p "$OUT_DIR"

if ! command -v flatpak-builder >/dev/null; then
  echo "flatpak-builder is required" >&2
  exit 1
fi

echo "==> Ensure Flathub remote and GNOME 48 Platform/SDK"
flatpak remote-add --if-not-exists --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install -y --user flathub \
  "org.gnome.Platform//48" \
  "org.gnome.Sdk//48"

echo "==> flatpak-builder (pip needs --share=network via manifest build-args)"
flatpak-builder --user --repo="$REPO_DIR" --force-clean "$BUILD_DIR" "$MANIFEST"
flatpak build-bundle "$REPO_DIR" "$BUNDLE" "$APP_ID"

echo "Wrote $BUNDLE"
