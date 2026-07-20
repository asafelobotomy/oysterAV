# ADR-008: Host Co-Control for ClamAV Threats

## Status

Accepted

## Context

oysterAV orchestrates ClamAV (ADR-001 / ADR-004) but does not replace the host
daemon. Today:

- `clamonacc.prevention` is a **preference** only (`config.toml`).
- Aggregate status hardcodes `clamonacc_prevention_enforced = false` — oysterAV
  never writes `OnAccessPrevention` into host `clamd.conf`.
- Process-mode on-access starts `clamonacc --fdpass` (detect-oriented path lists
  under XDG). Distro-unit mode enables `clamav-clamonacc` and defers watch paths
  / prevention to **host** ClamAV config.
- Post-scan findings already have rich response (quarantine vault, rkhunter
  overlays). On-access hits are not yet bridged into that pipeline.

Desktop users who set `clamonacc.prevention=true` see a health banner that
honestly says oysterAV does not manage host blocking — but the product goal is
stronger: **full co-control** with the host for detected-threat surfaces, without
overriding distro ownership of the daemon.

ClamAV has **no** rkhunter-style `clamd.conf.d` fragment merge. Fedora’s
`/etc/clamd.d/` holds **named instance** configs (`clamd@scan`), not layered
overlays. Silent rewrites of package-managed conf are rejected by mature
packagers and break upgrades (`.rpmnew` / `.dpkg-dist` / debconf).

## Decision

**Co-control, never override.**

oysterAV shares responsibility with the host for **detected-threat** surfaces
(detect, notify, quarantine, block-*intent*, audit). Prefer working **in concert**.
**Hand off** to the host/admin when the host is better equipped or the action
cannot be shared safely.

Wholesale rewrite of `/etc/clamav/clamd.conf`, `/etc/clamd.d/scan.conf`, or any
full daemon instance file is **forever out of scope**.

### Ownership matrix

| Layer | Host owns | oysterAV owns | Hand off when |
|-------|-----------|---------------|---------------|
| Engine identity (`User`, socket, MaxThreads, mail/`clamd@` instances) | Yes | Probe + doctor only | Foreign instance, debconf ownership, `.rpmnew`/`.dpkg-dist` conflict |
| On-access **block** (`OnAccessPrevention`) | Yes (kernel + daemon conf) | Intent (`clamonacc.prevention`) + probe truth | Kernel lacks `ACCESS_PERMISSIONS`; `OnAccessMountPath` in use; cannot verify safely |
| Watch paths | Distro unit → host conf; process mode → oysterAV lists | CLI list files / future unit drop-in for `--fdpass` | Distro unit present → host paths are authoritative |
| Signatures / ignores | Official CVD + DB dir | `oysterav.ign2`, fangfrisch, YARA drop-ins (already) | — |
| Quarantine / notify / confirm UI | Optional host `VirusEvent` / SIEM AR | oysterAV vault, history findings, audit trail | Host `VirusEvent` already set to a non-oysterAV script |
| Unit lifecycle | Distro units | polkit `systemctl` / process start via helper | Flatpak → host-packaged `oyst-cli` |

### Safe co-control mechanisms (allowed)

1. **Probe + guide** — discover conf/units; classify capability; doctor / health.
2. **systemd unit drop-ins** — e.g. ensure `--fdpass` on the clamonacc unit without copying vendor units.
3. **CLI overlays** — `clamonacc --include-list` / `--exclude-list` / `--move` (process mode).
4. **DB drop-ins** — `oysterav.ign2`, YARA, fangfrisch (existing pattern).
5. **VirusEvent script** — ship an oysterAV handler that reads **environment variables
   only** (never `%f` on the argv); set `VirusEvent` only when unset or already
   oysterAV-marked.
6. **Surgical key ensure** (future, high bar) — whitelist of keys only, backup,
   conflict → handoff. Not Phase 0.

### Safety rules (any future privileged process)

- Deny-list for prevention watch roots: `/`, `/usr`, `/etc`, `/var`, and other
  system trees that can soft-lock a desktop.
- Require `OnAccessExcludeUname` matching the daemon `User` (loop prevention).
- Never clobber a foreign `VirusEvent` or a mail/amavis `clamd@` instance.
- Restart order: **clamd** → wait/ping socket → **clamonacc**.
- `--confirm` + security audit for every privileged mutation.
- After package upgrades, detect `.rpmnew` / `.dpkg-dist` and hand off to the admin.
- `OnAccessPrevention` is incompatible with `OnAccessMountPath`; blocking uses
  `OnAccessIncludePath` only (upstream).

### Prior art

| Source | Mirror | Refuse |
|--------|--------|--------|
| ClamAV upstream | Configure `clamd`, connect clients; VirusEvent via env vars | Second scanning engine in app code |
| systemd | Unit drop-ins under `*.d/` | Copying vendor units into `/etc` and editing wholesale |
| Fedora/RHEL ClamAV | `clamd@scan` + `/etc/clamd.d/scan.conf` | Silent package/`%post` rewrites of instance conf |
| Debian/Ubuntu | debconf-managed `/etc/clamav/clamd.conf` | Fighting `dpkg-reconfigure` ownership |
| ClamTk | On-demand UI; user quarantine | Desktop GUI rewriting daemon policy |
| Wazuh / OSSEC | ClamAV = detect/log; active response = separate policy | SIEM owning ClamAV daemon config |
| ArchWiki notify recipes | VirusEvent → notify script | Filenames on VirusEvent argv (`%f` disabled upstream) |

In-tree analogs oysterAV already uses: `/etc/rkhunter.d/oysterav-*.conf`,
fail2ban `jail.d/oysterav-*-ignore.conf`, `oysterav.ign2`, fangfrisch into the
ClamAV DB dir, polkit `oyst-helper` argv templates.

### Multi-distro stance

Do not hardcode a single conf path. Discover via portable probes (see
[operator guide](../user-guide/clamonacc-prevention.md)). Typical layouts
(verify on the host):

| Family | Typical conf | Daemon unit | On-access unit | Notes |
|--------|--------------|-------------|----------------|-------|
| Arch / CachyOS | `/etc/clamav/clamd.conf` | `clamav-daemon` | `clamav-clamonacc` (if packaged) | Often process-mode if unit absent |
| Debian / Ubuntu | `/etc/clamav/clamd.conf` | `clamav-daemon` (+ socket) | varies | debconf owns file |
| Fedora / RHEL | `/etc/clamd.d/scan.conf` | `clamd@scan` | `clamav-clamonacc` | Instance file, not fragment merge |
| openSUSE | `/etc/clamd.conf` or clamav paths | distro units | varies | Confirm with `systemctl` / `clamconf` |
| Flatpak GUI | N/A inside sandbox | host units | host | Elevate via host `oyst-cli`; host ClamAV required |

### Roadmap (future code — not this ADR’s implementation)

| Phase | Goal |
|-------|------|
| **0** (this ADR) | Document co-control + operator guide |
| **1** | Multi-distro **probe** + classify: `impossible` \| `notify_only` \| `block_misconfigured` \| `blocking` \| `handoff_required` |
| **2** | Honest health banner from probe (replace hardcoded `prevention_enforced=false`) |
| **3** | Threat-response bridge: VirusEvent → oysterAV quarantine/notify/audit; CLI first (ADR-002); fix process-mode `--exclude-list` helper allowlist debt |
| **4** (deferred) | Safe concert: systemd `--fdpass` drop-in; optional surgical ensure of whitelisted OnAccess keys when unmarked/conflict-free; else handoff |

GUI surfaces for any of the above follow ADR-007 (CLI/RPC first; no silent
GUI-only host edits).

### Explicit non-goals (Phase 0)

- No runtime probe or helper writers in this change set.
- No GUI prevention toggle yet.
- No claim that `--fdpass` alone enables blocking (`OnAccessPrevention` is separate).
- No owning `/` (or equivalent) under prevention.

## Consequences

- Operators and agents treat host ClamAV as a partner: oysterAV states intent and
  response policy; the host engine performs fanotify block when configured.
- Health messaging may stay “unmanaged” until Phase 1–2 land; that is intentional
  honesty, not a license to rewrite conf.
- Future privileged ClamAV mutations must match the safety rules above and the
  existing overlay/helper style used for rkhunter and fail2ban.
- Operator steps live in [docs/user-guide/clamonacc-prevention.md](../user-guide/clamonacc-prevention.md).

## References

- [ClamAV On-Access](https://docs.clamav.net/manual/OnAccess.html)
- [ClamAV Configuration](https://docs.clamav.net/manual/Usage/Configuration.html)
- [ClamAV Packages](https://docs.clamav.net/manual/Installing/Packages.html)
- [systemd.unit(5) — overriding vendor settings](https://man.archlinux.org/man/systemd.unit.5)
- [Wazuh ClamAV log collection](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/clam-av-logs-collection.html)
- [ArchWiki ClamAV](https://wiki.archlinux.org/title/ClamAV)
- ADR-001, ADR-002, ADR-004, ADR-006, ADR-007; [pack-commands.md](../cli/pack-commands.md);
  [ADR index](README.md)
