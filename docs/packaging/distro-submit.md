# Distro / storefront submissions

oysterAV ships community binaries on [GitHub Releases](https://github.com/asafelobotomy/oysterAV/releases).
This document tracks **external** storefronts. Prefer GitHub Releases until a row
below says **Available**.

| Track | Status | Notes |
|-------|--------|-------|
| **AUR** (`oysterav`) | Pending listing | [`packaging/arch/`](../arch/) + [AUR checklist](release.md#aur-update-checklist-each-version-bump) + [`scripts/publish_aur.sh`](../../scripts/publish_aur.sh) |
| **Flathub** | Pending listing | Offline manifest: [`packaging/oysterav/flatpak/flathub/`](../oysterav/flatpak/flathub/) |
| **Fedora COPR** | Pending listing | Spec: [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec) |
| **PyPI** | Pending publish | Workflow: [`.github/workflows/publish-pypi.yml`](../../.github/workflows/publish-pypi.yml) |
| **Debian mentors** | Deferred | Scaffold: [`packaging/debian/`](../debian/); GitHub fpm `.deb` stays the Debian-user artifact |

## Privileged helper rule

Storefront packages must install `oyst-helper` under a **root-owned** `/usr` prefix
and ship [`packaging/polkit/io.github.asafelobotomy.policy`](../polkit/io.github.asafelobotomy.policy).
Flatpak GUI installs still need a **host** package for Polkit elevation
([Flatpak README](../oysterav/flatpak/README.md)).

## External submit checklist (after a GitHub Release)

1. **AUR:** `REQUIRE_SHA256=1 bash scripts/render_arch_pkgbuild.sh`, then
   `bash scripts/publish_aur.sh` (or push to `ssh://aur@aur.archlinux.org/oysterav.git`).
2. **COPR:** create project `asafelobotomy/oysterav`, build from tag source +
   [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec).
3. **Flathub:** open new-app PR from [`packaging/oysterav/flatpak/flathub/`](../oysterav/flatpak/flathub/)
   (not the GitHub CI dir-source manifest).
4. **PyPI:** configure Trusted Publisher + `pypi` environment; run
   `publish-pypi.yml` for the release tag.
5. Flip this table (and the README install table) to **Available** when each listing is live.
