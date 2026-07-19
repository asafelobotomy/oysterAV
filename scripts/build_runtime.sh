#!/usr/bin/env bash
# Build per-arch runtime tarball (tools only; ClamAV sigs via freshclam on first run).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="${1:-$(uname -m)}"
OUT="${ROOT}/dist/runtime-${ARCH}.tar.zst"
STAGING="${ROOT}/.runtime-staging/${ARCH}"

rm -rf "${STAGING}"
mkdir -p "${STAGING}/bin"

echo "Building runtime staging for ${ARCH}…"

# Lynis (pin must match oyst_core/runtime/checksums.json key lynis-3.1.7)
LYNIS_VER="3.1.7"
LYNIS_SHA256="48d829d0dc2c583a3e838cc09a7190b69a3af844bcb913c7cf9c0226b04b95c5"
curl -fsSL "https://codeload.github.com/CISOfy/lynis/tar.gz/refs/tags/${LYNIS_VER}" -o /tmp/lynis.tar.gz
echo "${LYNIS_SHA256}  /tmp/lynis.tar.gz" | sha256sum -c -
tar -xzf /tmp/lynis.tar.gz -C "${STAGING}"
mv "${STAGING}/lynis-${LYNIS_VER}" "${STAGING}/lynis"

# Copy system ClamAV tools when available (portable seed)
for tool in clamscan freshclam clamdscan clamd; do
  if command -v "${tool}" >/dev/null 2>&1; then
    cp "$(command -v "${tool}")" "${STAGING}/bin/${tool}"
  fi
done

mkdir -p "${ROOT}/dist"
tar -C "${STAGING}" -cf - . | zstd -19 -o "${OUT}"
echo "Wrote ${OUT}"
