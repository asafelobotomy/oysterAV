# Releasing oysterAV

## Cut a release

1. Ensure `main` is green (`./scripts/check.sh`).
2. Bump the single source of truth (example uses `0.2.2` — replace with the new version):
   ```bash
   echo "0.2.2" > VERSION
   python scripts/sync_version.py
   ```
3. Commit both `VERSION` and synced files (`pyproject.toml`, `oyst_core/__init__.py`, `oysterav/__init__.py`, and packaging embeds when they changed: Flatpak metainfo, Arch PKGBUILD / `.SRCINFO`, RPM spec `Version:`, Debian changelog top entry, Flathub manifest tag + sha256):
   ```bash
   git add VERSION pyproject.toml oyst_core/__init__.py oysterav/__init__.py
   git commit -m "chore(release): 0.2.2"
   git push origin main
   ```
4. GitHub Actions [`.github/workflows/release.yml`](../../.github/workflows/release.yml) detects the `VERSION` change, tags `v0.2.2`, builds assets, and publishes a [GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).
   The publish job runs in the `release` environment, so a required reviewer must approve it.
5. After the release is published, `release.yml` dispatches [`publish-pypi.yml`](../../.github/workflows/publish-pypi.yml) (`tag=v0.2.2`). That workflow uploads to PyPI with Trusted Publishing (environment `pypi`). A dispatch is needed because a release created with `GITHUB_TOKEN` never fires `release: published`.

### Release workflow hardening

- The version (dispatch input or `VERSION`) must match `^v?X.Y.Z$`, otherwise the workflow fails. Dispatch inputs reach shell steps only through `env:`.
- The workflow default is `contents: read`. Only `prepare` (pushes the tag) and `release` (publishes assets and pushes `CHANGELOG.md`) get `contents: write`. The `pypi` job gets `actions: write`, which it needs to dispatch the PyPI workflow. Every checkout uses `persist-credentials: false`. The push steps pass the token to `git` only for that one command.
- `fpm` is pinned (`gem install fpm -v 1.17.0`).

**One-time repository settings:**

- Create the `release` environment (Settings → Environments) with required reviewers. You can also restrict it to the `main` branch.
- Keep the `pypi` environment, and keep the PyPI Trusted Publisher pointing at `publish-pypi.yml` / `pypi`.

Do **not** push an annotated tag yourself unless you know the release workflow already skipped (duplicate tag is ignored).

After publish, `oyst-cli version --check` compares the installed build to that latest GitHub Release.

`RUNTIME_VERSION` in `oyst_core/runtime/manifest.py` is a separate schema pin for Full-mode runtime locks — bump it only when the runtime lock format changes.

## Changelog

| Output | Source | Where |
|--------|--------|--------|
| **Release body** | `git cliff --latest` | GitHub Release notes for that tag |
| **Full history** | `git cliff` (all tags) | [`CHANGELOG.md`](../../CHANGELOG.md) committed to `main` as `docs(changelog): vX.Y.Z` |

Both use [`cliff.toml`](../../cliff.toml). Updating `CHANGELOG.md` alone does **not** re-trigger Release (path filter is `VERSION` only).

## Force republish / repair a stuck tag

If a tag exists but the GitHub Release is missing or assets need rebuilding:

1. Open **Actions → Release → Run workflow**.
2. Leave **version** empty (uses the `VERSION` file) or set it to the tag without the leading `v` (e.g. `0.2.2`).
3. Enable **force** so an existing tag is rebuilt and the release is created/updated.
   Force is refused unless the workflow is dispatched from `main` (`refs/heads/main`).
4. Force builds from the **workflow commit** (current `main` tip) so packaging fixes apply. It then attaches the assets to the existing tag, overwriting any with the same name, and marks the release latest.
5. Confirm assets and a `docs(changelog): v…` commit land on `main`.

## Release assets (core set)

| Asset | Purpose |
|-------|---------|
| `*.whl` / `*.tar.gz` | Python package (CLI via `uv`/`pip`) |
| `runtime-x86_64.tar.zst` | Full-mode seed tarball ([ADR-004](../adr/004-pack-runtime-delivery.md)) |
| `oysterAV-*-x86_64.flatpak` | GTK4 GUI Flatpak bundle |
| `oysterav_*_all.deb` | Debian/Ubuntu package (app + desktop + icons + polkit helper); Debian 13+ / Ubuntu 25.04+ (pydantic 2) |
| `oysterav-*-1.noarch.rpm` | Fedora/RHEL-style package |
| `SHA256SUMS` | `sha256sum` of every other asset (`sha256sum -c SHA256SUMS` to verify; not signed) |
| `PKGBUILD` + `SRCINFO` | Arch packaging template for `makepkg` / AUR (leading-dot `.SRCINFO` is published as `SRCINFO` because GitHub Release assets cannot start with `.`) |

## Formats not shipped

| Format | Why skipped |
|--------|-------------|
| **AppImage** | oysterAV is a host-integrated orchestrator (polkit helper, ClamAV, GTK introspection). A self-contained AppImage fights that model and still needs host security tools. |
| **Snap** | Same host-integration tension; Flatpak already covers GNOME desktops. |

GitHub Releases remain the source of truth for community **`.deb` / `.rpm` / `.flatpak`**
binaries. Distro storefronts (AUR, Flathub, COPR, PyPI) are separate submission tracks —
see [docs/packaging/distro-submit.md](distro-submit.md).

## AUR update checklist (each VERSION bump)

1. `python scripts/sync_version.py` (updates metainfo + renders PKGBUILD).
2. After the GitHub tag exists: `REQUIRE_SHA256=1 bash scripts/render_arch_pkgbuild.sh`.
   Then re-run `python scripts/sync_version.py` so the Flathub manifest picks up the
   archive sha256. Once tag `v<VERSION>` exists locally, `sync_version.py --check`
   fails while PKGBUILD/.SRCINFO still say `sha256sums=SKIP` (`--strict-sha256`
   enforces this even before the tag exists).
3. Copy `packaging/arch/PKGBUILD` and `packaging/arch/.SRCINFO` into the AUR git clone.
4. `makepkg --printsrcinfo > .SRCINFO` (optional verify) and `git push` to `ssh://aur@aur.archlinux.org/oysterav.git`.

## Local packaging helpers

```bash
python scripts/sync_version.py --check
bash scripts/build_runtime.sh x86_64
bash scripts/render_arch_pkgbuild.sh
# Requires flatpak-builder + GNOME 50 runtime/SDK (pip needs network inside the SDK):
bash scripts/build_flatpak.sh x86_64
# Requires fpm (gem install fpm -v 1.17.0, as in CI) + rpm tools:
PYTHON_BIN="$(uv run which python)" bash scripts/build_native_packages.sh x86_64
```

## Privileged helper path

Distro packages and `oyst-cli install-privileged-helper` install `oyst-helper` to `/usr/lib/oysterav/oyst-helper` (polkit `exec.path`). Legacy `/usr/local/lib/oysterav/oyst-helper` is still detected for status/resolution.

## Compatibility sunsets (0.3.0)

Warn throughout **0.2.x**; remove in **0.3.0**:

| Legacy | 0.2.x behavior | 0.3.0 plan |
|--------|----------------|------------|
| `runtime.clamav_profile` config key / CLI alias | Maps to `scan.clamav_profile`; emits `DeprecationWarning` on get/set and on TOML migrate | Remove alias + `[runtime].clamav_profile` migrate in `config_access` / `config_io` |
| `HELPER_PATH_LEGACY` (`/usr/local/lib/oysterav/oyst-helper`) | Still resolved after `/usr/lib` for status/reinstall cleanup | Drop detection if unused; keep `/usr/lib` only |
| `LEGACY_PROFILES` schedule units (`oyst-scan-{profile}.*`) | `_remove_legacy_units()` migrates old timers on schedule install | Delete migration once changelog notes “legacy timers unsupported” |

Prefer `scan.clamav_profile` and the packaged helper path for all new installs.

### Native package layout (deb/rpm)

`scripts/build_native_packages.sh` builds architecture-independent packages: the
wheel is unpacked (no bundled dependencies) into the private, root-owned prefix
`/usr/lib/oysterav/python`, and `/usr/bin/oyst-cli`, `/usr/bin/oysterav` and
`/usr/lib/oysterav/oyst-helper` are `#!/usr/bin/python3 -I` launchers that insert
that prefix. Runtime dependencies come from distro packages. Before upload, the
release workflow install-tests both packages in Debian 13, Ubuntu 26.04 and
Fedora containers via `scripts/smoke_native_packages.sh dist`; run the same
script locally with podman or docker.

### Verifying downloads

Every release asset is listed in `SHA256SUMS` and carries a Sigstore build-provenance
attestation from the release workflow. Verify a download with the GitHub CLI:

```bash
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify oysterav_0.2.2_all.deb --repo asafelobotomy/oysterAV
```
