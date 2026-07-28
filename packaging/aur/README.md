# AUR package: oysterav

Rendered sources of truth live in [`../arch/`](../arch/) (`PKGBUILD`, `.SRCINFO`).

## First-time submit

1. Create an AUR account (if needed) and add an SSH public key under
   https://aur.archlinux.org/ (logged-in account → SSH Public Keys).
2. **Verify your AUR account email** (required before any `git push`).
3. Create the empty package repo:

```bash
ssh aur@aur.archlinux.org setup-repo oysterav
```

4. From the oysterAV checkout:

```bash
REQUIRE_SHA256=1 bash scripts/render_arch_pkgbuild.sh
bash scripts/publish_aur.sh
```

5. Confirm https://aur.archlinux.org/packages/oysterav

Optional local SSH config (IdentityFile pointing at the key you registered):

```sshconfig
Host aur.archlinux.org
  IdentityFile ~/.ssh/id_ed25519_aur
  IdentitiesOnly yes
```

## Updates

Follow the [AUR checklist](../../docs/packaging/release.md#aur-update-checklist-each-version-bump)
after each `VERSION` bump / GitHub Release.
