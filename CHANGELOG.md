# Changelog

All notable changes to oysterAV are documented here and on each
[GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).
## 0.4.0 - 2026-11-17

### Features

- `oyst-cli status summary` now includes the firewall (ufw) and, with `--deep`, Bindle's boot-guard check; a failing check turns the state to "needs attention"
- A security shield in uQ's bar (green, amber, red) with a popup of the reasons, and a notification when the state gets worse
- Live check that runs the shield in the real uQ shell on a headless Hyprland

## 0.3.0 - 2026-11-16

### Bug Fixes

- *(release)* Unblock tag builds on sha256sums=SKIP; harden uv cache for v10 (#33)


### Miscellaneous

- *(packaging)* Pin v0.2.3 checksums

- *(deps)* Bump ossf/scorecard-action from 2.4.3 to 2.4.4 (#14)

- *(deps)* Bump pypa/gh-action-pypi-publish from 1.12.4 to 1.14.2 (#17)


### Other

- *(deps)* Bump github/codeql-action/upload-sarif (#30)

- *(deps)* Bump astral-sh/setup-uv from 9.0.0 to 10.2.0 (#31)

- *(deps)* Bump softprops/action-gh-release from 2.2.2 to 3.0.3 (#32)

- *(deps)* Bump ruff from 0.16.4 to 0.16.10 (#26)

- *(deps)* Bump click from 8.4.2 to 8.5.0 (#28)

- *(deps)* Bump mypy from 2.3.0 to 2.4.0 (#29)

- *(deps)* Bump actions/upload-artifact from 7.0.1 to 7.0.2 (#34)

- *(deps)* Bump actions/download-artifact from 8.0.1 to 8.0.2 (#35)

- *(deps)* Bump mypy from 2.4.0 to 2.4.1 (#40)

- *(deps)* Bump github/codeql-action/upload-sarif (#38)

- *(deps)* Bump orhun/git-cliff-action from 4.8.0 to 4.9.1 (#39)

- *(deps)* Bump ossf/scorecard-action from 2.4.4 to 2.5.0 (#36)

- *(deps)* Bump pytest from 9.1.1 to 9.2.0 (#42)

- *(deps)* Bump pydantic from 2.13.4 to 2.14.0 (#27)

- *(deps)* Bump ruff from 0.16.10 to 0.17.3 (#41)

- *(deps)* Bump certifi from 2026.7.22 to 2026.10.18

- Merge pull request #43 from asafelobotomy/cursor/certifi-fangfrisch-bump-828c

- Add setup permissions remediation plan

- Project files: CODE_OF_CONDUCT.md, CODEOWNERS, CONTRIBUTING.md, .editorconfig, .gitattributes, issue template, pull_request_template.md

- Slim AGENTS.md: move gates, GUI remapping status, debug/release, learned notes to docs/agents/

- UQ integration: cheap status summary --json, Security tile and Settings page (#49)

- *(deps)* Bump github/codeql-action/upload-sarif (#47)

- *(deps)* Bump softprops/action-gh-release from 3.0.3 to 3.0.4 (#46)

- *(deps)* Bump astral-sh/setup-uv from 10.2.0 to 10.3.3 (#45)

- *(deps)* Bump pypa/gh-action-pypi-publish from 1.14.2 to 1.14.3 (#44)

- *(deps)* Bump pydantic from 2.14.0 to 2.14.3 (#48)

- *(deps)* Bump ruff from 0.17.3 to 0.17.4 (#51)

- *(deps)* Bump click from 8.5.0 to 8.5.1 (#50)

- Rebuild the uQ Security page: tabs, streamed scans, previews, preferences (#52)

## 0.2.3 - 2026-10-11

### Bug Fixes

- *(flatpak)* Migrate to GNOME 50 and tolerate missing loginctl

- *(security)* Close workspace audit residuals

- *(tests)* Unbreak CI failures masked by ruff format gate

- *(security,ux)* Close full-surface audit and first-run setup gaps

- *(security)* Harden privileged helper boundary

- *(core)* Scan correctness, quarantine safety, jobs, RPC and network

- *(ci)* Skip widget tests without a display; import ParseError from defusedxml

- *(clamav)* Working clamd backend, private signature timer, cancellable scans


### CI

- Harden release workflow and make security gates real


### Documentation

- *(changelog)* V0.2.2

- *(packaging)* Withdraw Flathub; clarify AUR/COPR/PyPI human gates

- *(packaging)* Mark PyPI available; defer COPR; note AUR email verify

- *(packaging)* Mark AUR oysterav 0.2.2-1 as available

- Refresh GUI screenshots and README for six-tab UI

- Record 2026-10-11 full-surface audit and update guides


### Features

- *(gui)* Separate oyst-cli serve backend; fix GUI/CLI audit findings


### Miscellaneous

- *(packaging)* Pin v0.2.2 checksums and Flathub submit status

- *(lock)* Sync uv.lock to oysterav 0.2.2

- *(deps)* Land Dependabot bumps and unblock CI


### Other

- Add Ko-fi donation button

- *(packaging)* Arch-independent deb/rpm with container install tests


### Styling

- Apply ruff format to helper install test


### Testing

- Compare IPv4-mapped addresses by value, not str()

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


