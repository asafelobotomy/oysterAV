# Distro / storefront submissions

oysterAV ships community binaries on [GitHub Releases](https://github.com/asafelobotomy/oysterAV/releases)
(current: **v0.2.2**). Prefer GitHub Releases until a row below says **Available**.

| Track | Status | Notes |
|-------|--------|-------|
| **AUR** (`oysterav`) | Pending — AUR SSH key | PKGBUILD ready; add an AUR account SSH key, `ssh aur@aur.archlinux.org setup-repo oysterav`, then `bash scripts/publish_aur.sh` |
| **Flathub** | Pending review | Submission PR: https://github.com/flathub/flathub/pull/9533 (manifest in [`packaging/oysterav/flatpak/flathub/`](../oysterav/flatpak/flathub/), pinned to `v0.2.2`) |
| **Fedora COPR** | Pending — create project | Spec: [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec); create `asafelobotomy/oysterav` on [COPR](https://copr.fedorainfracloud.org/) |
| **PyPI** | Pending — Trusted Publisher | GitHub environment `pypi` exists; register Trusted Publisher at [pypi.org](https://pypi.org/manage/account/publishing/) (repo `oysterAV`, workflow `publish-pypi.yml`, env `pypi`), then re-run `publish-pypi.yml` for `v0.2.2` |
| **Debian mentors** | Deferred | Scaffold: [`packaging/debian/`](../debian/); GitHub fpm `.deb` stays the Debian-user artifact |

## Privileged helper rule

Storefront packages must install `oyst-helper` under a **root-owned** `/usr` prefix
and ship [`packaging/polkit/io.github.asafelobotomy.policy`](../polkit/io.github.asafelobotomy.policy).
Flatpak GUI installs still need a **host** package for Polkit elevation
([Flatpak README](../oysterav/flatpak/README.md)).

## External submit checklist (after a GitHub Release)

1. **AUR:** register AUR SSH key → `setup-repo oysterav` → `bash scripts/publish_aur.sh`.
2. **COPR:** create project + SCM build from tag + [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec).
3. **Flathub:** respond to review on [PR #9533](https://github.com/flathub/flathub/pull/9533); `bot, build` when asked.
4. **PyPI:** finish Trusted Publisher; re-run `publish-pypi.yml` for the tag.
5. Flip this table (and the README install table) to **Available** when each listing is live.
