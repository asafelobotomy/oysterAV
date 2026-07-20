#!/usr/bin/env bash
# Build DEB and RPM packages via fpm (x86_64 / amd64).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
ARCH="${1:-x86_64}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
STAGE="${FPM_STAGE:-$ROOT/.fpm-staging}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "$OUT_DIR"
rm -rf "$STAGE"
mkdir -p "$STAGE"

if ! command -v fpm >/dev/null; then
  echo "fpm is required (gem install fpm)" >&2
  exit 1
fi

echo "==> Sync version"
"$PYTHON_BIN" scripts/sync_version.py

echo "==> Stage install under $STAGE/usr"
# uv-managed interpreters often lack pip; prefer uv pip when available.
if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$PYTHON_BIN" --prefix="$STAGE/usr" .
else
  "$PYTHON_BIN" -m pip install --upgrade pip
  "$PYTHON_BIN" -m pip install --prefix="$STAGE/usr" .
fi

# Normalize lib path (Debian uses lib/python3.x, some use lib64).
HELPER_DIR="$STAGE/usr/lib/oysterav"
mkdir -p "$HELPER_DIR"
cat >"$HELPER_DIR/oyst-helper" <<'EOF'
#!/usr/bin/env python3
from oyst_core.privileged.oyst_helper import main
main()
EOF
chmod 755 "$HELPER_DIR/oyst-helper"

mkdir -p "$STAGE/usr/bin"
ln -sfn ../lib/oysterav/oyst-helper "$STAGE/usr/bin/oyst-helper"

echo "==> Desktop, icons, polkit, metainfo"
install -Dm644 packaging/oysterav/io.github.asafelobotomy.OysterAV.desktop \
  "$STAGE/usr/share/applications/io.github.asafelobotomy.OysterAV.desktop"
install -Dm644 packaging/oysterav/flatpak/io.github.asafelobotomy.OysterAV.metainfo.xml \
  "$STAGE/usr/share/metainfo/io.github.asafelobotomy.OysterAV.metainfo.xml"
install -Dm644 packaging/polkit/io.github.asafelobotomy.policy \
  "$STAGE/usr/share/polkit-1/actions/io.github.asafelobotomy.policy"

for size in 16 32 48 128 256; do
  install -Dm644 "branding/hicolor/${size}x${size}/apps/oysterav.png" \
    "$STAGE/usr/share/icons/hicolor/${size}x${size}/apps/oysterav.png"
done
install -Dm644 branding/oysterAV-icon.png \
  "$STAGE/usr/share/icons/hicolor/512x512/apps/oysterav.png"

AFTER_INSTALL="$ROOT/packaging/fpm/after-install.sh"
mkdir -p "$ROOT/packaging/fpm"

DEB_ARCH=amd64
RPM_ARCH=x86_64
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
  DEB_ARCH=arm64
  RPM_ARCH=aarch64
fi

COMMON_ARGS=(
  -s dir
  -C "$STAGE"
  --name oysterav
  --version "$VERSION"
  --iteration 1
  --license "GPL-3.0-or-later"
  --url "https://github.com/asafelobotomy/oysterAV"
  --description "Linux security orchestrator: oyst-cli backend + oysterAV GTK4 GUI"
  --maintainer "oysterAV contributors"
  --after-install "$AFTER_INSTALL"
  --depends python3
  usr
)

echo "==> Build DEB"
fpm -t deb -f "${COMMON_ARGS[@]}" \
  --architecture "$DEB_ARCH" \
  --package "$OUT_DIR/oysterav_${VERSION}_${DEB_ARCH}.deb" \
  --depends python3-gi \
  --depends gir1.2-gtk-4.0 \
  --depends gir1.2-adw-1 \
  --depends policykit-1

echo "==> Build RPM"
fpm -t rpm -f "${COMMON_ARGS[@]}" \
  --architecture "$RPM_ARCH" \
  --package "$OUT_DIR/oysterav-${VERSION}-1.${RPM_ARCH}.rpm" \
  --depends python3-gobject \
  --depends gtk4 \
  --depends libadwaita \
  --depends polkit

echo "Wrote:"
ls -la "$OUT_DIR"/oysterav*"${VERSION}"* || true
