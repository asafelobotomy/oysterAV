# Changelog

All notable changes to oysterAV are documented here and on each
[GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).
## Unreleased

### Documentation

- *(changelog)* V0.2.0

- *(changelog)* V0.2.0


### Other

- Harden privileged paths, RPC, and quarantine after security audits.

- Document ClamAV host co-control and refresh the README with GUI shots.

- Install cairo/GObject headers in CI so uv sync --extra all can build pycairo.

- Harden auth status for unreadable polkit paths and relax GUI parity exits.

- Silence intentional bandit medium findings with nosec markers.

- Harden release CI for Flatpak network, force republish, and full changelog.

- Fix force release builds to use workflow HEAD and uv pip for fpm staging.

- Fix fpm flag order so architecture and package options precede the path.

- Include .SRCINFO in GitHub Release uploads (dotfile glob fix).

- Upload hidden .SRCINFO via include-hidden-files on the arch artifact.

- Publish Arch SRCINFO without a leading dot for GitHub Releases.

## 0.2.0 - 2026-07-20

### Other

- Bootstrap oysterAV with ADR-007 docs and workspace hygiene.

- Ship the full GPLv3 license text for GPL-3.0-or-later.

- Point project identity at github.com/asafelobotomy/oysterAV.

- Add packaging and release pipeline for distro assets.

- Enforce a 400-line hard limit on production Python.

- Split oversized oyst_core modules under the 400-line limit.

- Split CLI packs package and schedule command for LOC.

- Split GUI widgets and fix Settings pane bugs.


