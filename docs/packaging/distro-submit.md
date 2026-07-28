# Distro / storefront submissions

oysterAV ships community binaries on [GitHub Releases](https://github.com/asafelobotomy/oysterAV/releases)
(current: **v0.2.2**). Prefer GitHub Releases until a row below says **Available**.

| Track | Status | Notes |
|-------|--------|-------|
| **AUR** (`oysterav`) | Pending — verify AUR email | SSH works; empty `oysterav` repo created and local commit ready. AUR rejects pushes until the account email is verified on the [AUR profile](https://aur.archlinux.org/). Then `bash scripts/publish_aur.sh` (or `git -C .aur-oysterav push origin master`). |
| **Flathub** | Not pursuing | [PR #9533](https://github.com/flathub/flathub/pull/9533) withdrawn: Flathub [generative AI policy](https://docs.flathub.org/docs/for-app-authors/requirements#generative-ai-policy). GitHub Release `.flatpak` remains available. |
| **Fedora COPR** | Deferred | Spec ready at [`packaging/rpm/oysterav.spec`](../rpm/oysterav.spec); skipped for now. |
| **PyPI** | Available | https://pypi.org/project/oysterav/ (`0.2.2`). CLI discoverability; prefer system packages for Polkit helper. |
| **Debian mentors** | Deferred | Scaffold: [`packaging/debian/`](../debian/); GitHub fpm `.deb` stays the Debian-user artifact |

## Privileged helper rule

Storefront packages must install `oyst-helper` under a **root-owned** `/usr` prefix
and ship [`packaging/polkit/io.github.asafelobotomy.policy`](../polkit/io.github.asafelobotomy.policy).
Flatpak GUI installs still need a **host** package for Polkit elevation
([Flatpak README](../oysterav/flatpak/README.md)).

## Remaining human gates

1. **AUR:** verify email on AUR profile → `bash scripts/publish_aur.sh` → flip this table + README to Available.
2. **COPR:** deferred (optional later).
3. **Flathub:** closed under current policy.
4. **PyPI:** done for `v0.2.2`.
