# Fedora COPR

Spec file: [`oysterav.spec`](oysterav.spec).

**Status:** deferred — no public COPR project yet. Prefer the GitHub Release `.rpm`
or wait until [distro submit status](../../docs/packaging/distro-submit.md) marks
COPR as Available.

## Publish (when ready)

1. Create a COPR project (e.g. `asafelobotomy/oysterav`) at https://copr.fedorainfracloud.org/
2. Add a package that builds from the GitHub tag tarball / this `.spec`
   (SCM method: `https://github.com/asafelobotomy/oysterAV.git`, path `packaging/rpm/oysterav.spec`)
3. Enable for Fedora current + EPEL as desired
4. After the first successful build, users install with:

```bash
dnf copr enable asafelobotomy/oysterav
dnf install oysterav
```

GitHub Release `.rpm` files from fpm remain a separate community binary channel.
