# Flathub submission

This directory holds the **offline-capable** Flatpak manifest for Flathub review
(pinned PyPI wheels + GitHub tag archive). GitHub Release CI still builds the
host-checkout (dir-source) manifest at
[`../io.github.asafelobotomy.OysterAV.yml`](../io.github.asafelobotomy.OysterAV.yml) —
do not submit that CI manifest to Flathub.

Binary wheels such as `pydantic-core` are pinned twice with `only-arches`
(`x86_64` and `aarch64`) for the GNOME 48 runtime CPython ABI (`cp313`).

## Submit

1. Fork https://github.com/flathub/flathub and open a PR adding app id
   `io.github.asafelobotomy.OysterAV` (new-app workflow per Flathub docs).
2. Point the Flathub package repo at this manifest (or copy into the Flathub
   app repository once the bot creates it).
3. Expect review questions about `--filesystem=host` and dual-install for the
   Polkit helper (Flatpak GUI + host AUR/deb/rpm package).

## Dual-install (required)

Flatpak cannot install a root-owned `oyst-helper` by itself. Users need:

- Flatpak: GUI client
- Host package (AUR / COPR / GitHub `.deb`/`.rpm`): `oyst-cli` + polkit policy

See the AppStream description in
[`../io.github.asafelobotomy.OysterAV.metainfo.xml`](../io.github.asafelobotomy.OysterAV.metainfo.xml).
