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

echo "==> Build wheel"
WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "$WHEEL_DIR"' EXIT
if command -v uv >/dev/null 2>&1; then
  uv build --wheel --out-dir "$WHEEL_DIR" .
else
  "$PYTHON_BIN" -m pip wheel --no-deps --wheel-dir "$WHEEL_DIR" .
fi
WHEEL="$(ls "$WHEEL_DIR"/oysterav-*.whl)"

# Pure-Python app: unpack into a private, version-independent, root-owned prefix
# (no site-packages vs dist-packages mismatch, no build-host interpreter in
# shebangs). Runtime deps come from distro packages (--depends), never bundled.
APP_LIB=/usr/lib/oysterav/python
echo "==> Stage $WHEEL into $STAGE$APP_LIB"
mkdir -p "$STAGE$APP_LIB"
"$PYTHON_BIN" -m zipfile -e "$WHEEL" "$STAGE$APP_LIB"
# Root-owned, not group/world-writable: the helper trust check requires it.
chmod -R u=rwX,go=rX "$STAGE$APP_LIB"

# Launchers: system python3 in isolated mode (-I ignores PYTHON* env, cwd and
# user site), with the private prefix inserted explicitly.
write_launcher() {
  local dest="$1" module="$2"
  mkdir -p "$(dirname "$dest")"
  printf '%s\n' \
    "#!/usr/bin/python3 -I" \
    "import sys" \
    "sys.path.insert(0, \"$APP_LIB\")" \
    "from $module import main" \
    "sys.exit(main())" >"$dest"
  chmod 755 "$dest"
}
write_launcher "$STAGE/usr/bin/oyst-cli" oyst_cli.main
write_launcher "$STAGE/usr/bin/oysterav" oysterav.main
write_launcher "$STAGE/usr/lib/oysterav/oyst-helper" oyst_core.privileged.oyst_helper
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
install -Dm644 branding/hicolor/512x512/apps/oysterav.png \
  "$STAGE/usr/share/icons/hicolor/512x512/apps/oysterav.png"

AFTER_INSTALL="$ROOT/packaging/fpm/after-install.sh"
AFTER_REMOVE="$ROOT/packaging/fpm/after-remove.sh"
mkdir -p "$ROOT/packaging/fpm"

# Pure Python: architecture-independent packages ($ARCH kept for CLI compat).
: "$ARCH"
DEB_ARCH=all
RPM_ARCH=noarch

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
  --after-remove "$AFTER_REMOVE"
  --deb-user root --deb-group root
  --rpm-user root --rpm-group root
)

echo "==> Build DEB"
fpm -t deb -f "${COMMON_ARGS[@]}" \
  --architecture "$DEB_ARCH" \
  --package "$OUT_DIR/oysterav_${VERSION}_${DEB_ARCH}.deb" \
  --depends "python3 (>= 3.12)" \
  --depends python3-click \
  --depends "python3-pydantic (>= 2)" \
  --depends python3-defusedxml \
  --depends python3-gi \
  --depends gir1.2-gtk-4.0 \
  --depends gir1.2-adw-1 \
  --depends "pkexec | policykit-1" \
  --depends "polkitd | policykit-1" \
  usr

echo "==> Build RPM"
fpm -t rpm -f "${COMMON_ARGS[@]}" \
  --architecture "$RPM_ARCH" \
  --package "$OUT_DIR/oysterav-${VERSION}-1.${RPM_ARCH}.rpm" \
  --depends "python3 >= 3.12" \
  --depends python3-click \
  --depends "python3-pydantic >= 2" \
  --depends python3-defusedxml \
  --depends python3-gobject \
  --depends gtk4 \
  --depends libadwaita \
  --depends polkit \
  usr

echo "Wrote:"
ls -la "$OUT_DIR"/oysterav*"${VERSION}"* || true
