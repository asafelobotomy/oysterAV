# Debian / Ubuntu packaging (mentors track — deferred)

This tree is a **scaffold** toward a mentors-ready source package. Until it
ships through Debian/Ubuntu, install the **GitHub Release `.deb`** (fpm community
binary) from https://github.com/asafelobotomy/oysterAV/releases.

Desktop, metainfo, polkit, and icons are listed in `oysterav.install`. `rules`
adds the `/usr/bin/oyst-helper` symlink after pybuild install and installs
`oyst-helper.in` as `/usr/lib/oysterav/oyst-helper` (`execute_after_dh_install`;
`dh_install` cannot rename). The compat level comes from `debhelper-compat (= 13)`
in `control` (no `debian/compat`). `source/format` is `3.0 (quilt)` to match the
`0.2.2-1` Debian revision (needs an `oysterav_0.2.2.orig.tar.gz` upstream tarball).

## Remaining work for mentors

1. Move or symlink this `debian/` directory to the source root for `dpkg-buildpackage`
2. Prefer system Python deps over vendored site-packages (see `control`)
3. File an ITP and upload to mentors

Do not treat this scaffold as upload-ready.
