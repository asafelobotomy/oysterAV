# Flathub offline manifest (reference)

This directory holds an **offline-capable** Flatpak manifest (pinned PyPI wheels +
GitHub tag archive). GitHub Release CI builds the host-checkout (dir-source)
manifest at
[`../io.github.asafelobotomy.OysterAV.yml`](../io.github.asafelobotomy.OysterAV.yml).

## Flathub status — not pursuing

Flathub listing is **not being pursued**: Flathub’s
[generative AI policy](https://docs.flathub.org/docs/for-app-authors/requirements#generative-ai-policy)
disallows AI-assisted applications. Keep this offline manifest for reference /
possible future policy change; ship users the **GitHub Release Flatpak** bundle instead.

Binary wheels such as `pydantic-core` are pinned twice with `only-arches`
(`x86_64` and `aarch64`) for the GNOME 50 runtime CPython ABI (`cp313`).

## Dual-install (required for any Flatpak GUI)

Flatpak cannot install a root-owned `oyst-helper` by itself. Users need:

- Flatpak: GUI client
- Host package (AUR / GitHub `.deb`/`.rpm`): `oyst-cli` + polkit policy

See the AppStream description in
[`../io.github.asafelobotomy.OysterAV.metainfo.xml`](../io.github.asafelobotomy.OysterAV.metainfo.xml).
