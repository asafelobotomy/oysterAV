# Distro / storefront submissions

oysterAV ships community binaries on [GitHub Releases](https://github.com/asafelobotomy/oysterAV/releases)
(current: **v0.2.2**). Prefer GitHub Releases until a row below says **Available**.

| Track | Status | Notes |
|-------|--------|-------|
| **AUR** (`oysterav`) | Pending — AUR SSH key | PKGBUILD ready; no local SSH identity. Create/register an AUR key, `ssh aur@aur.archlinux.org setup-repo oysterav`, then `bash scripts/publish_aur.sh` |
| **Flathub** | Pending — PR closed for checklist; updated | [PR #9533](https://github.com/flathub/flathub/pull/9533) (closed by bot). Checklist restored; manifest migrated to **GNOME 50**. Needs: reviewer reopen + Flatpak screencast attachment |
| **Fedora COPR** | Pending — create project | Spec: [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec); create `asafelobotomy/oysterav` on [COPR](https://copr.fedorainfracloud.org/) (no `copr-cli` credentials here) |
| **PyPI** | Pending — Trusted Publisher | GitHub env `pypi` exists; register at [pypi.org publishing](https://pypi.org/manage/account/publishing/) then re-run `publish-pypi.yml` for `v0.2.2` |
| **Debian mentors** | Deferred | Scaffold: [`packaging/debian/`](../debian/); GitHub fpm `.deb` stays the Debian-user artifact |

## Privileged helper rule

Storefront packages must install `oyst-helper` under a **root-owned** `/usr` prefix
and ship [`packaging/polkit/io.github.asafelobotomy.policy`](../polkit/io.github.asafelobotomy.policy).
Flatpak GUI installs still need a **host** package for Polkit elevation
([Flatpak README](../oysterav/flatpak/README.md)).

## External submit checklist (after a GitHub Release)

1. **AUR:** register AUR SSH key → `setup-repo oysterav` → `bash scripts/publish_aur.sh`.
2. **COPR:** create project + SCM build from tag + [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec).
3. **Flathub:** complete screencast on [PR #9533](https://github.com/flathub/flathub/pull/9533); ask for reopen / `/review`; `bot, build` when asked.
4. **PyPI:** finish Trusted Publisher; re-run `publish-pypi.yml` for the tag.
5. Flip this table (and the README install table) to **Available** when each listing is live.
