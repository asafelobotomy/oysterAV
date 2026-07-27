# Changelog

All notable changes to oysterAV are documented here and on each
[GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).
## 0.2.2 - 2026-07-27

### Bug Fixes

- *(packaging)* Harden storefronts and honest install docs


### Documentation

- *(changelog)* V0.2.1


### Miscellaneous

- *(packaging)* Sync debian/rpm changelogs for 0.2.2

## 0.2.1 - 2026-07-27

### Bug Fixes

- *(helper)* Allow clamonacc --exclude-list in privileged argv

- *(cli)* Require setup --confirm and align concert RPC/GUI UX


### CI

- Raise coverage floor, block Scorecard, add Semgrep/Gitleaks


### Documentation

- *(changelog)* V0.2.0

- *(changelog)* V0.2.0

- *(changelog)* V0.2.0

- Mark Wave 4 residual as permanent CLI-first

- *(ci)* Sync contracts, pin release Actions, and refresh agent notes

- Record full-surface audit remediations and sync contracts


### Features

- *(config)* Deprecate runtime.clamav_profile toward the 0.3.0 sunset

- *(clamav)* Ship ADR-008 Phase 3–4.1 host co-control and VirusEvent

- *(privilege)* Privilege Concert, setup hardenings, and bulk install UX

- *(privilege)* Add update-concert for single-auth Update all

- *(gui)* Add Scan Results pack copy and progress helpers

- *(gui)* Extend StatusCard for select, wrap, and progress fill

- *(gui)* Wire profile-aware Scan Results cards and custom picks

- Managed firewall lifecycle, Shield UI, and security test gates

- *(shield)* Structured UFW rules with multi-add/delete in one auth

- *(security)* Harden privileged paths and add attacker-sim gates

- *(gui)* Ship desktop branding icons and duration-ordered scan cards


### Miscellaneous

- Prune dead code and split orchestrator under the LOC limit


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

- Enhance job control commands to include force-clear functionality for active scan locks. Update documentation and user guides to reflect new preferences and workspace facts. Implement health assessment improvements for on-access prevention configurations. Add tests for job cancellation and lock clearing behaviors.

- Seal helper argv/tarball paths and harden grant/quarantine

- Scrub command env and broaden audit path redaction

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


