# Changelog

All notable changes to oysterAV are documented here and on each
[GitHub Release](https://github.com/asafelobotomy/oysterAV/releases).

## Unreleased

### Security

- Privilege Concert (policy **v11**, [ADR-009](docs/adr/009-privilege-concert.md)):
  multi-step elevated actions disclose a plan, then authenticate once via
  allowlisted recipes (`setup-concert`, `setup-harden`, `scan-concert`). Integrity
  / audit packs run first in one concert; clamav/maldet follow without further
  prompts. Passwordless YES scope unchanged (lifecycle only). Phase 2: rkhunter
  Resolve uses the same façade (`resolve-rkhunter` recipe) with existing
  `rkhunter-whitelist set-many` (no new polkit action). Bulk Install All /
  Update all / Harden / Auto-Install share priority-ordered plan disclosure
  (required → recommended → optional → harden → propupd).

- Audit remediation (2026-07): `run-sealed` validates scanner argv like `run`;
  `install-script` re-verifies the maldet **tarball** SHA and extracts under a
  root seal (no install.sh-only seal); scan-concert fails closed on unknown
  `--pack=`; quarantine `add` uses `O_NOFOLLOW`; auth-grant fails closed without
  expire timer; PrivilegePlan disclosure-only for Install All / Update all;
  full-mode Install All honors checklist selection; scan reports owned by
  `PKEXEC_UID`. Reinstall helper after pull for site_root code updates.

- Passwordless service-lifecycle grant narrowed (policy **v10**): YES only for
  `systemctl-up` (ClamAV/maldet start/enable/restart) and `maldet-config`; requires
  active local session; 7-day TTL with auto-revoke timer. Stop/disable and
  fail2ban/firewalld stay passworded. Helper install migrates legacy broad
  `systemctl` YES grants.

- Maldet findings parse only real `{hit}` / `session.hits` lines (no false HIGH from
  `{scan}` summaries or `found clamav binary`); self-hits under `maldetect/sigs/` are
  dropped from malware findings. Quarantine `add` is copy→INSERT→unlink (no orphan
  vault files without a DB row); auto-quarantine refuses scanner bindirs / basenames
  and maldet signature packs. Privileged helper policy **v9** adds `run-sealed`:
  hash-verify a runtime integrity scanner, copy to `/var/lib/oysterav/sealed/`, then
  exec (never exec user-writable runtime paths directly as root).

- Hardening audit (July 2026): `clamonacc` list paths and `lynis --profile` open
  with `O_NOFOLLOW` (reject symlinks / world-writable lists; root-owned profiles);
  XDG data dir mode `0700`; `SECURITY.md`, OpenSSF Scorecard workflow, Dependabot,
  and pinned CI Actions with read-only default `GITHUB_TOKEN` permissions. See
  `docs/security/hardening-audit-2026-07.md`.

### Fixed

- Maldet event log / session hits resolve under runtime `pub/<user>/` in full mode;
  ClamAV and maldet conf default excludes cover vault + LMD sigs/pub. chkrootkit /
  rkhunter / unhide report a clear message when only a runtime install is present
  and privileged scan needs a system package or sealed helper.

- `quarantine verify` reports orphans; `quarantine reconcile --delete-orphans`
  cleans them (reinstall helper for policy v9 if `run-sealed` is missing).

- First-run Auto-Install / `setup run` uses one `setup-concert` polkit prompt for
  official packs, propupd, harden/firewall, and linger (policy version 8). AUR
  installs remain outside the concert.

- Audit logs redact `/home/…` paths; `events.db` and `oyst-cli.log` are mode 0600;
  pkexec inherits a scrubbed environment; helper site_root must be root-owned.

- First-run hardenings use a single `setup-harden` polkit action so "Apply
  recommended hardenings" prompts for a password once.

- UFW rule builder: emit `22/tcp` (and `proto … to any port …` with `--from`) so
  `firewall ensure-enable` SSH allow no longer hits "Wrong number of arguments".

- Source/dev installs: embed absolute `oyst_core` site root in `oyst-helper` so
  pkexec (cwd=/) can import the package under system Python.

### Added

- Bulk actions + collapsible checklists: Settings **Update all** expander,
  Packs **Install All** (full → selected `runtime.install` packs; lite →
  setup-concert priority order), wizard Harden / Auto-Install recipe SwitchRows,
  Quarantine open confirm lists capped paths. Privilege Concert façade
  ([ADR-009](docs/adr/009-privilege-concert.md)) discloses ordered steps.

- First-run safe host hardenings (ADR-008 Phase 4.2): Auto-Install / `setup run`
  applies clamd ensure, fdpass, VirusEvent, DisableCache, and rkhunter defaults;
  SSH-safe `firewall ensure-enable`; wizard Host hardening page. Prevention stays
  Real-time after path selection.

- Security news: openSUSE/SUSE announce feed, broader default sources, and a
  freshness window (`ui.security_news_max_age_days`, default 14; Settings 7/14/30).

- ADR-008 Phase 4.1 co-control robustness: preserve vendor `clamonacc` ExecStart when
  ensuring `--fdpass`; expose package conf sidecars in probe/health; wait for clamd
  socket before restarting clamonacc; `oyst-cli clamav ensure-disable-cache`.

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


