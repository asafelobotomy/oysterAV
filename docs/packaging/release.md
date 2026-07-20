# Releasing oysterAV

## Cut a release

1. Ensure `main` is green (`./scripts/check.sh`).
2. Bump the single source of truth:
   ```bash
   echo "0.2.0" > VERSION
   python scripts/sync_version.py
   ```
3. Commit both `VERSION` and synced files (`pyproject.toml`, `oyst_core/__init__.py`, `oysterav/__init__.py`):
   ```bash
   git add VERSION pyproject.toml oyst_core/__init__.py oysterav/__init__.py
   git commit -m "chore(release): 0.2.0"
   git push origin main
   ```
4. GitHub Actions [`.github/workflows/release.yml`](../../.github/workflows/release.yml) detects the `VERSION` change, tags `v0.2.0`, builds assets, and publishes a [GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).

Do **not** push an annotated tag yourself unless you know the release workflow already skipped (duplicate tag is ignored).

`RUNTIME_VERSION` in `oyst_core/runtime/manifest.py` is a separate schema pin for Full-mode runtime locks — bump it only when the runtime lock format changes.

## Changelog

| Output | Source | Where |
|--------|--------|--------|
| **Release body** | `git cliff --latest` | GitHub Release notes for that tag |
| **Full history** | `git cliff` (all tags) | [`CHANGELOG.md`](../../CHANGELOG.md) committed to `main` as `docs(changelog): vX.Y.Z` |

Both use [`cliff.toml`](../../cliff.toml). Updating `CHANGELOG.md` alone does **not** re-trigger Release (path filter is `VERSION` only).

## Force republish / repair a stuck tag

If a tag exists but the GitHub Release is missing or assets need rebuilding (e.g. `v0.2.0` after a failed run):

1. Open **Actions → Release → Run workflow**.
2. Leave **version** empty (uses the `VERSION` file) or set it to `0.2.0`.
3. Enable **force** so an existing tag is rebuilt and the release is created/updated.
4. Force builds from the **workflow commit** (current `main` tip) so packaging fixes apply, then attaches assets to the existing tag.
5. Confirm assets and a `docs(changelog): v…` commit land on `main`.

## Release assets (core set)

| Asset | Purpose |
|-------|---------|
| `*.whl` / `*.tar.gz` | Python package (CLI via `uv`/`pip`) |
| `runtime-x86_64.tar.zst` | Full-mode seed tarball ([ADR-004](../adr/004-pack-runtime-delivery.md)) |
| `oysterAV-*-x86_64.flatpak` | GTK4 GUI Flatpak bundle |
| `oysterav_*_amd64.deb` | Debian/Ubuntu package (app + desktop + icons + polkit helper) |
| `oysterav-*-1.x86_64.rpm` | Fedora/RHEL-style package |
| `PKGBUILD` + `.SRCINFO` | Arch packaging template for `makepkg` / AUR |

## Formats not shipped

| Format | Why skipped |
|--------|-------------|
| **AppImage** | oysterAV is a host-integrated orchestrator (polkit helper, ClamAV, GTK introspection). A self-contained AppImage fights that model and still needs host security tools. |
| **Snap** | Same host-integration tension; Flatpak already covers GNOME desktops. |
| **Flathub / PyPI** | Not wired in v1 — Flatpak/wheel attach to GitHub Releases only. |

## Local packaging helpers

```bash
python scripts/sync_version.py --check
bash scripts/build_runtime.sh x86_64
bash scripts/render_arch_pkgbuild.sh
# Requires flatpak-builder + GNOME 48 runtime/SDK (pip needs network inside the SDK):
bash scripts/build_flatpak.sh x86_64
# Requires fpm (gem install fpm) + rpm tools:
PYTHON_BIN="$(uv run which python)" bash scripts/build_native_packages.sh x86_64
```

## Privileged helper path

Distro packages and `oyst-cli install-privileged-helper` install `oyst-helper` to `/usr/lib/oysterav/oyst-helper` (polkit `exec.path`). Legacy `/usr/local/lib/oysterav/oyst-helper` is still detected for status/resolution.
