# ClamAV YARA drop-in rules

## Status

Supported as a documentation convention — **not** a separate oysterAV pack.

## Why not a YARA pack?

ClamAV already loads files ending in `.yar` / `.yara` from its database directory
([ClamAV YARA rules](https://docs.clamav.net/manual/Signatures/YaraRules.html)).
Linux Malware Detect also ships native YARA scanning. A third standalone YARA
engine would duplicate UX without improving desktop coverage.

## How to use custom rules with oysterAV

1. Prefer **full mode** so the DB dir is writable under
   `$XDG_DATA_HOME/oysterav/runtime/<arch>/clamav/db/`.
2. Copy (or symlink) rule files into that directory (or `/var/lib/clamav` in lite mode).
3. Run `oyst-cli freshclam update` (and `oyst-cli fangfrisch refresh` if installed)
   so ClamAV reloads databases when using clamd (`clamdscan --reload` / restart clamd).
4. Confirm with `oyst-cli fangfrisch status --json` — `details.yara_rules_in_db` counts
   `*.yar` / `*.yara` files present.

## Fangfrisch

Optional pack `fangfrisch` downloads unofficial signature providers into the same
ClamAV DB directory **after** official CVD updates from freshclam. It may also
deliver YARA-based databases from configured providers. See
`oyst-cli fangfrisch --help`.

Default providers: `sanesecurity`, `urlhaus`. Change with:

```bash
oyst-cli config set fangfrisch.providers sanesecurity,urlhaus
oyst-cli fangfrisch ensure-config --force
```

## Ignoring false-positive signatures

Unofficial signatures often end in `.UNOFFICIAL`. Whitelist noisy names via:

```bash
oyst-cli config set clamav.ignore_sigs Sanesecurity.Spam.12345,Other.Sig.1
```

oysterAV writes `oysterav.ign2` into the active ClamAV DB directory (full-mode
runtime DB or `/var/lib/clamav` in lite mode). In lite mode that directory is
usually owned by `clamav`; when it isn't writable, scans still run and `doctor`
reports that the ignore list can't be applied (use full mode). Reload clamd
after changes when using the daemon backend.

## Scan limits and linux-only profile

```bash
oyst-cli config set scan.max_filesize 50M
oyst-cli config set scan.exclude_dirs ~/.cache,~/.local/share/Trash
oyst-cli config set scan.clamav_profile linux-only   # clamscan --scan-pe=no
```

These apply to **clamscan** only. `clamdscan` limits remain in host `clamd.conf`
(oysterAV does not manage that file). `runtime.mode` (`full`/`lite`) is install
delivery and is unrelated to `scan.clamav_profile`.

## clamd backend

`scan.backend auto` picks clamd only when it answers `PING`, and only in
**lite** mode. In full mode `auto` stays on clamscan, because clamd loads the
host's definitions (`/var/lib/clamav`) and never sees oysterAV's private DB or
`oysterav.ign2`. `--backend clamd` still forces the daemon.

How oysterAV calls `clamdscan`:

- `--config-file=` the first readable host conf that sets `LocalSocket` /
  `TCPSocket` (`/etc/clamav/clamd.conf`, `/etc/clamd.d/scan.conf`,
  `/etc/clamd.conf`). With no readable conf, a 0600
  `~/.local/share/oysterav/clamdscan.conf` naming only the discovered socket.
- `--fdpass` on a Unix socket, so clamd (running as `clamav` / `clamscan`) can
  read files in your home folder. Not used over TCP.
- `--multiscan` for the `full` and `suite` profiles.
- No `-r`, `--database`, limits or `--exclude-dir` (clamdscan ignores them).
  Findings under `scan.exclude_dirs` and oysterAV's own folders (quarantine
  vault, maldet signatures) are dropped after the scan instead.

## Keeping definitions fresh

Signature age (`oyst-cli freshclam status`, `doctor`) is measured on the
database scans actually load: the private runtime DB when it holds `.cvd` /
`.cld` files, otherwise the host DB. Both ages are in `doctor --json`
(`runtime_age_hours`, `host_age_hours`).

In **full** mode oysterAV installs a user timer, `oyst-signatures.timer`, that
runs `oyst-cli freshclam update --fangfrisch` every 6 hours (30 min jitter,
catches up after sleep). No password is needed. It is turned on by the full
runtime bootstrap and when switching `runtime.mode` to full, and removed in lite
mode, which keeps using the distro's `clamav-freshclam` timer.

```bash
oyst-cli services set freshclam-timer off   # full mode: opt out (persists)
oyst-cli services set freshclam-timer on
oyst-cli config set runtime.auto_update_signatures false   # same switch
```

## Version advisory

The minimum supported ClamAV is 1.4.0. `doctor` and `status assess` also warn,
without blocking, when a supported line lacks current security fixes: below
1.4.6 on 1.4.x, or below 1.5.4 on 1.5.x.

## Cancel and timeouts

Cancelling a scan stops a running `clamscan` / `clamdscan` within about a second
(SIGTERM, then SIGKILL after 5 s). Detections printed before the stop are kept;
results may be incomplete. A scan still running after 2 hours is stopped the
same way and reported as a pack error with its partial findings.

## On-access prevention

Real fanotify **blocking** (`OnAccessPrevention`) is host-owned; oysterAV
co-controls intent, response, and probing without rewriting package daemon
config. See [ADR-008](../adr/008-clamav-host-cocontrol.md) and the
[clamonacc prevention operator guide](../user-guide/clamonacc-prevention.md).
On-access hits can bridge into quarantine/audit via
`oyst-cli virusevent` (Phase 3).
