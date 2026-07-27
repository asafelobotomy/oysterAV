#!/usr/bin/env bash
# Push packaging/arch PKGBUILD + .SRCINFO to the AUR package repo.
# Requires SSH access: ssh://aur@aur.archlinux.org/oysterav.git
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

AUR_DIR="${AUR_DIR:-$ROOT/.aur-oysterav}"
AUR_REMOTE="${AUR_REMOTE:-ssh://aur@aur.archlinux.org/oysterav.git}"

export REQUIRE_SHA256=1
bash scripts/render_arch_pkgbuild.sh

if [[ ! -d "$AUR_DIR/.git" ]]; then
  echo "==> Cloning AUR package into $AUR_DIR"
  git clone "$AUR_REMOTE" "$AUR_DIR"
fi

cp packaging/arch/PKGBUILD "$AUR_DIR/PKGBUILD"
cp packaging/arch/.SRCINFO "$AUR_DIR/.SRCINFO"

cd "$AUR_DIR"
if command -v makepkg >/dev/null 2>&1; then
  makepkg --printsrcinfo > .SRCINFO
fi

git add PKGBUILD .SRCINFO
if git diff --cached --quiet; then
  echo "AUR package already up to date"
  exit 0
fi

VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
git commit -m "Update to ${VERSION}"
echo "==> Pushing to ${AUR_REMOTE}"
git push origin master
echo "AUR oysterav updated to ${VERSION}"
