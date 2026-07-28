# Distro / storefront submissions

oysterAV ships community binaries on [GitHub Releases](https://github.com/asafelobotomy/oysterAV/releases)
(current: **v0.2.2**). Prefer GitHub Releases until a row below says **Available**.

| Track | Status | Notes |
|-------|--------|-------|
| **AUR** (`oysterav`) | Pending — needs AUR account SSH | PKGBUILD ready (`REQUIRE_SHA256=1`). Register an SSH public key on [AUR account → SSH Keys](https://aur.archlinux.org/account/), then `ssh aur@aur.archlinux.org setup-repo oysterav` and `bash scripts/publish_aur.sh`. See [`packaging/aur/README.md`](../aur/README.md). |
| **Flathub** | Not pursuing | [PR #9533](https://github.com/flathub/flathub/pull/9533) withdrawn: Flathub [generative AI policy](https://docs.flathub.org/docs/for-app-authors/requirements#generative-ai-policy) disallows AI-assisted apps. GitHub Release `.flatpak` remains available. |
| **Fedora COPR** | Pending — create project | Spec: [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec); create `asafelobotomy/oysterav` on [COPR](https://copr.fedorainfracloud.org/) (SCM: this GitHub repo, path `packaging/rpm/oysterav.spec`). |
| **PyPI** | Pending — Trusted Publisher | GitHub environment `pypi` exists. Register Trusted Publisher at [pypi.org](https://pypi.org/manage/account/publishing/) (owner `asafelobotomy`, repo `oysterAV`, workflow `publish-pypi.yml`, environment `pypi`), then run `publish-pypi.yml` for `v0.2.2`. |
| **Debian mentors** | Deferred | Scaffold: [`packaging/debian/`](../debian/); GitHub fpm `.deb` stays the Debian-user artifact |

## Privileged helper rule

Storefront packages must install `oyst-helper` under a **root-owned** `/usr` prefix
and ship [`packaging/polkit/io.github.asafelobotomy.policy`](../polkit/io.github.asafelobotomy.policy).
Flatpak GUI installs still need a **host** package for Polkit elevation
([Flatpak README](../oysterav/flatpak/README.md)).

## External submit checklist (human gates)

1. **AUR:** AUR SSH key on account → `setup-repo oysterav` → `bash scripts/publish_aur.sh` → flip this table + README to Available.
2. **COPR:** create project + SCM build from tag → flip docs when the first build succeeds.
3. **Flathub:** closed — do not resubmit under current Flathub generative AI policy.
4. **PyPI:** Trusted Publisher on pypi.org → re-run `publish-pypi.yml` for the tag → flip docs.
5. Flip README install rows only when a listing is actually live.
