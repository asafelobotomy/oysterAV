# AUR package: oysterav

Rendered sources of truth live in [`../arch/`](../arch/) (`PKGBUILD`, `.SRCINFO`).

## First-time submit

1. Create the empty AUR package (https://aur.archlinux.org/submit) named `oysterav`
   or: `ssh aur@aur.archlinux.org setup-repo oysterav` (after SSH key is registered).
2. From the oysterAV checkout:

```bash
REQUIRE_SHA256=1 bash scripts/render_arch_pkgbuild.sh
bash scripts/publish_aur.sh
# or manually clone ssh://aur@aur.archlinux.org/oysterav.git and copy PKGBUILD/.SRCINFO
```

3. Confirm https://aur.archlinux.org/packages/oysterav

## Updates

Follow the [AUR checklist](../../docs/packaging/release.md#aur-update-checklist-each-version-bump)
after each `VERSION` bump / GitHub Release.
