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
runtime DB or `/var/lib/clamav` in lite mode). Reload clamd after changes when
using the daemon backend.

## Scan limits and linux-only profile

```bash
oyst-cli config set scan.max_filesize 50M
oyst-cli config set scan.exclude_dirs ~/.cache,~/.local/share/Trash
oyst-cli config set scan.clamav_profile linux-only   # clamscan --scan-pe=no
```

These apply to **clamscan** only. `clamdscan` limits remain in host `clamd.conf`
(oysterAV does not manage that file). `runtime.mode` (`full`/`lite`) is install
delivery and is unrelated to `scan.clamav_profile`.

## On-access prevention

Real fanotify **blocking** (`OnAccessPrevention`) is host-owned; oysterAV
co-controls intent, response, and probing without rewriting package daemon
config. See [ADR-008](../adr/008-clamav-host-cocontrol.md) and the
[clamonacc prevention operator guide](../user-guide/clamonacc-prevention.md).
On-access hits can bridge into quarantine/audit via
`oyst-cli virusevent` (Phase 3).
