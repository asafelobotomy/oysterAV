# Clamonacc prevention — operator guide

Multi-distro steps for **real on-access blocking** with ClamAV, in concert with
oysterAV. Policy and ownership: [ADR-008](../adr/008-clamav-host-cocontrol.md).

oysterAV stores **intent** (`clamonacc.prevention`) and response UX (quarantine,
audit). The **host** owns `OnAccessPrevention` and daemon identity. Do not
replace package-managed `clamd.conf` / `clamd.d` instance files wholesale.

## Prefer detect-only?

```bash
oyst-cli config set clamonacc.prevention false
oyst-cli status assess --json
```

On-access monitoring can stay enabled (`clamonacc.enabled`); only the
“prevention requested” health signal clears.

## Portable discovery (all distros)

Run these **on the host** (not only inside Flatpak). Paths and unit names vary —
treat the table in ADR-008 as hints, not guarantees.

### 1. Kernel capability

Blocking needs fanotify **access permissions**:

```bash
# Prefer the running kernel config when available:
grep -E 'CONFIG_FANOTIFY(_ACCESS_PERMISSIONS)?=' /boot/config-$(uname -r) 2>/dev/null
# or:
zgrep -E 'CONFIG_FANOTIFY(_ACCESS_PERMISSIONS)?=' /proc/config.gz 2>/dev/null
```

Expect both `CONFIG_FANOTIFY=y` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`.
If access-permissions is missing, only **notify-only** on-access is possible —
hand off / keep `clamonacc.prevention false`.

### 2. Find ClamAV config and units

```bash
# Units (names differ by distro):
systemctl list-unit-files '*clam*' --no-pager

# Common conf roots (inspect what exists):
ls -la /etc/clamav/ /etc/clamd.d/ /etc/clamd.conf 2>/dev/null

# If clamconf is installed:
clamconf -n 2>/dev/null | head
```

Typical pairs (verify locally):

| Family | Conf | Daemon | On-access |
|--------|------|--------|-----------|
| Arch / CachyOS | `/etc/clamav/clamd.conf` | `clamav-daemon` | `clamav-clamonacc` or process-mode |
| Debian / Ubuntu | `/etc/clamav/clamd.conf` | `clamav-daemon` | packaged unit if any |
| Fedora / RHEL | `/etc/clamd.d/scan.conf` | `clamd@scan` | `clamav-clamonacc` |
| openSUSE | check `clamconf` / `/etc` | distro units | distro units |

### 3. oysterAV mode

```bash
oyst-cli config get clamonacc.prevention
oyst-cli clamonacc status --json
oyst-cli services status --json   # kind: systemctl vs process
```

- **`kind: systemctl`** — distro unit; **host conf paths are authoritative**.
  oysterAV XDG include/exclude lists apply to **process mode** only.
- **`kind: process`** — oysterAV starts `clamonacc --fdpass` with list files under
  `~/.local/share/oysterav/`.

## Blocking recipe (host)

Upstream requirement for **real block** (not MountPath):

1. Use **`OnAccessIncludePath`** for narrow trees you care about (e.g. Downloads).
2. Set **`OnAccessPrevention yes`**.
3. Set **`OnAccessExcludeUname`** to the same value as daemon **`User`**
   (often `clamav` or `clamscan` — read it from the conf you found).
4. Do **not** combine prevention with **`OnAccessMountPath`** (especially `/`).
5. Prefer **`--fdpass`** on `clamonacc` (systemd drop-in on the unit, or process
   argv) so unprivileged `clamd` can scan FDs from root `clamonacc`.

Example fragment (edit the **discovered** conf; do not invent a second full file
unless you intentionally run a separate `clamd@` instance):

```text
OnAccessIncludePath /home/YOURUSER/Downloads
OnAccessPrevention yes
OnAccessExcludeUname clamav
```

Then restart in order:

```bash
# Examples — use the units your discovery found:
sudo systemctl restart clamav-daemon    # or: clamd@scan
# wait for the local socket; then:
sudo systemctl restart clamav-clamonacc # if the unit exists
# or: oyst-cli clamonacc stop && oyst-cli clamonacc start
```

Optional: systemd drop-in for `--fdpass` (preferred over copying the vendor unit):

```bash
sudo systemctl edit clamav-clamonacc
# Add ExecStart= override / drop-in that includes --fdpass per distro unit layout
```

## When to hand off (do not force oysterAV)

Stop and leave the host/admin in charge if:

- Kernel lacks `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`.
- Conf is owned by mail/amavis (`clamd@` other than the desktop scan instance).
- `VirusEvent` already points at a non-oysterAV script.
- Package left `.rpmnew` / `.dpkg-dist` after an upgrade — merge manually.
- Debian/Ubuntu: prefer understanding `dpkg-reconfigure clamav-daemon` before
  fighting the file.
- Fedora/RHEL: SELinux may need `antivirus_can_scan_system` (distro docs).
- Flatpak-only install with no host `oyst-cli` / ClamAV — install host packages first.

## oysterAV preference vs host reality

`oyst-cli status assess` / the GUI health banner probe host `clamd.conf` for
`OnAccessPrevention` (ADR-008 Phase 1–2). When the host is configured for
blocking, `clamonacc_prevention_enforced` is true and the unmanaged banner
clears even though oysterAV still does not write the conf.

```bash
oyst-cli status assess --json
# Look for clamonacc_prevention_enforced / clamonacc_onaccess.classification
```

| Classification | Meaning |
|----------------|---------|
| `blocking` | Host has `OnAccessPrevention yes` without `OnAccessMountPath` conflict |
| `notify_only` | Prevention not enabled in conf |
| `block_misconfigured` | Prevention + MountPath (incompatible) |
| `impossible` | Kernel lacks fanotify access permissions |
| `handoff_required` | No readable conf among candidates |

If the banner remains after editing conf, restart **clamd** then **clamonacc**,
and re-run assess. Clearing intent without host blocking: set
`clamonacc.prevention false`.

## Related

- [ADR-008 Host co-control](../adr/008-clamav-host-cocontrol.md)
- [Pack commands — clamonacc](../cli/pack-commands.md)
- [ClamAV YARA / limits](../cli/clamav-yara.md)
- Upstream: [On-Access scanning](https://docs.clamav.net/manual/OnAccess.html)
