# Debian / Ubuntu packaging (mentors track — deferred)

This tree is a **scaffold** toward a mentors-ready source package. Until it
ships through Debian/Ubuntu, install the **GitHub Release `.deb`** (fpm community
binary) from https://github.com/asafelobotomy/oysterAV/releases.

Helper, desktop, metainfo, polkit, and icons are listed in `oysterav.install`;
`rules` only adds the `/usr/bin/oyst-helper` symlink after pybuild install.

## Remaining work for mentors

1. Move or symlink this `debian/` directory to the source root for `dpkg-buildpackage`
2. Prefer system Python deps over vendored site-packages (see `control`)
3. File an ITP and upload to mentors

Do not treat this scaffold as upload-ready.
