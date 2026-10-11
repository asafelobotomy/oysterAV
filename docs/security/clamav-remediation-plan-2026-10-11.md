# ClamAV remediation plan — group 1 (2026-10-11)

Source: ClamAV GUI landscape research (ClamTk, ClamUI v0.1–v0.4, upstream
ClamAV 1.5.x) cross-referenced with the oysterAV ClamAV surface. This plan
covers the five correctness/security items only.

**Status: implemented 2026-10-11** with the recommended decisions (D1 clamscan
in full mode, D2 timer auto-enabled in full mode, D3 masked original
permissions). See "Implementation notes" at the end.

Test host: Manjaro, ClamAV 1.5.4 (installed 2026-10-11 via pacman).

## Summary

| # | Item | Severity | Verified | PR |
|---|------|----------|----------|----|
| R1 | clamd scan path can never succeed | High | Yes (real clamdscan 1.5.4) | 1 |
| R2 | No security-patch advisory for old ClamAV | Medium | Code read | 1 |
| R3 | Full mode: private signatures never auto-update; age hides it | High | Code read | 2 |
| R4 | Quarantine drops original permissions | Low | Code read | 4 |
| R5 | Cancel can't stop a running scanner; timeout escapes | Medium | Code read (timeout path unverified) | 3 |

---

## R1 — clamd scan backend is broken

### Evidence

`ClamAVPack.scan()` ([clamav.py:244-265](../../oyst_core/packs/clamav.py)) builds:

```
clamdscan --config-file=/dev/null -r --stdout <target> --database=<runtime db>
```

Against real clamdscan 1.5.4 on this host:

- `--config-file=/dev/null` leaves clamdscan with no `LocalSocket`/`TCPSocket`,
  so it never even tries to connect. Result: `Total errors: 1`, exit 2. That
  raises `PartialScanError`, so every clamd scan reports failure.
- `-r` and `--database` give `WARNING: Ignoring unsupported option`.
- There is no `--fdpass`. Arch, Debian and Fedora all run clamd as a dedicated
  user (`clamav` / `clamscan`), which can't read `~/Downloads`. Even with the
  socket fixed, home-folder scans would hit "Permission denied" (exit 2).

Related gaps found during the read:

- `CLAMD_SOCKETS` has no entry for Fedora's `/run/clamd.scan/clamd.sock`.
- clamdscan ignores `--exclude-dir`, `--max-*` and `--scan-pe`, so the
  quarantine-vault and maldet-sig exclusions never apply on the clamd path.
  Scanning `~` would flag the vault's own `.bin` copies.
- In **full** mode clamd uses the host database (`/var/lib/clamav`), not the
  private runtime one. `oysterav.ign2` (written to the private DB dir) is also
  never seen by clamd, so ignored signatures come back.
- `auto` checks clamd with `pgrep` only; a running clamd with an unreachable
  socket still gets picked.

### Fix

New module `oyst_core/packs/clamd_client.py`. `clamav.py` is 325 lines, so
splitting keeps it under the 400-line limit.

1. **Endpoint discovery.**
   - Read `LocalSocket` / `TCPSocket` + `TCPAddr` from the first readable host
     conf. Reuse `_CONF_CANDIDATES` from `clamd_onaccess.py` (make it public).
   - The parser must strip ClamAV 1.5 inline `# comments`.
   - Fallback: the socket probe list plus `/run/clamd.scan/clamd.sock`.
2. **Config for clamdscan.**
   - Pass `--config-file=<host conf>` when it is readable.
   - Otherwise write a minimal 0600 conf containing only the discovered
     `LocalSocket` line to `$XDG_RUNTIME_DIR/oysterav/clamdscan.conf`.
   - Never use `/dev/null`.
3. **argv.**
   - Build `clamdscan --config-file=<conf> --stdout [--fdpass] [--multiscan] <target>`.
   - `--fdpass` only for a Unix socket (it can't work over TCP).
   - `--multiscan` only for `full` / `suite` profiles.
   - Drop `-r` and `--database`.
4. **Reachability.** In `auto`, choose clamd only if `clamdscan --ping 1`
   succeeds. 1.5's new `Enable*Command` switches don't cover PING.
5. **Exclusions.** For the clamd backend, post-filter findings under
   `merged_clamav_exclude_dirs()` by path prefix, so a vault hit is never
   reported or re-quarantined.
6. **Full mode.** `auto` prefers clamscan in full mode, so scans use the
   private signatures and `ign2`. An explicit `--backend clamd` still works,
   with a doctor note that it uses the host's signatures. **(Decision D1.)**
7. **Error detail.** On exit ≥ 2 with empty stderr, take the `ERROR:` lines
   from stdout for the `PartialScanError` message (clamdscan prints them there
   under `--stdout`).

### Tests

- Unit (`tests/test_core/`):
  - argv for clamscan vs clamd (Unix socket, TCP-only, no conf).
  - Inline-comment conf parsing.
  - The Fedora socket path.
  - Vault post-filter.
  - Full-mode `auto` → clamscan.
  - `--ping` failure → clamscan fallback.
- Security (`-m security`): the generated conf is 0600 and contains only the
  socket line; symlinks in the runtime dir are refused.
- Manual on this host: freshclam, start clamd through the existing
  `enable-stack` helper, then scan a file in `~/Downloads` and the EICAR test
  string with `--backend clamd`. Expect exit 1 and one finding.

### Docs

- `docs/cli/clamav-yara.md`: clamd backend behaviour, which options clamd
  ignores, the exclusion post-filter, full-mode database note.

---

## R2 — security-patch advisory

### Evidence

`min_version = "1.4.0"` ([clamav.py:43](../../oyst_core/packs/clamav.py)).
1.5.4 / 1.4.6 (2026-08-07) fix a clamd STATS crash and several CVEs (incl. the
bundled UnRAR); 1.5.3 fixes quarantine TOCTOU races.

### Fix

- Keep the hard floor at 1.4.0. Raising it would block users on distros that
  ship older patch releases.
- Add a small table `RECOMMENDED_PATCH = {(1, 4): "1.4.6", (1, 5): "1.5.4"}`.
  Below it, `version_ok` stays True, but `details["advisory"]` is set and the
  status message reads e.g. "ClamAV 1.5.2 is missing security fixes; update to
  1.5.4 or newer."
- Surface it through `doctor --json` and `status assess` (warning, not error).
  Plain language, no internal jargon.
- Bumping later is a one-line table change.

### Tests

Version matrix: 1.4.5 → advisory; 1.4.6 → none; 1.5.3 → advisory; 1.6.0 →
none (unknown newer line).

---

## R3 — full-mode signature updates

### Evidence

- In full mode, scans use `--database=<private runtime db>`. That database is
  only updated by Update all, first-run bootstrap, or Settings → Maintenance.
- The only timer oysterAV touches is the distro's `clamav-freshclam(.timer)`
  ([services.py:43](../../oyst_core/services.py)), which updates
  `/var/lib/clamav`.
- `FreshclamPack.signature_age_hours()`
  ([freshclam.py:72](../../oyst_core/packs/freshclam.py)) takes the **newest**
  file across the host and private databases. A fresh host database therefore
  hides a weeks-old private one, and the dashboard shows green while scans use
  stale signatures.

### Fix

1. **Age.** Measure the database scans actually use: private in full mode, host
   in lite mode. Report both in `details` (`runtime_age_hours`,
   `host_age_hours`).
2. **Update timer.** A user-level systemd timer `oyst-update.timer` (full mode
   only), running `oyst-cli freshclam update`, then `fangfrisch refresh` when
   enabled.
   - No root needed; the private DB is user-owned.
   - Schedule: every 6 h, `RandomizedDelaySec=30m`, `Persistent=true`. This
     respects ClamAV CDN rate limits.
   - New module `oyst_core/schedule_update_units.py`, reusing
     `_run_user_systemctl` / linger helpers. `schedule_units.py` is already
     387 lines.
3. **CLI first:** `oyst-cli schedule updates enable|disable|status [--json]`.
   Then RPC (`schedule.updates_*`), then an autosaving Settings toggle.
   - Update `docs/cli/gui-contract.md` and the parity tests in the same PR.
4. **Auto-enable** on full-mode bootstrap and when switching
   `runtime.mode` → full. Disable on switch to lite. **(Decision D2.)**
5. **Lite mode:** unchanged (distro timer). If the signatures are > 48 h old
   and the distro timer is inactive, doctor says so in plain language.

freshclam already downloads to a temp file and verifies before replacing, so
ClamUI-style staging is not needed.

### Tests

- Age selection per mode, including the "fresh host DB, stale private DB" case.
- Unit file rendering (no shell strings, argv tokens only, as ClamUI v0.3.0).
- Enable/disable on mode switch.
- CLI/RPC parity.

---

## R4 — quarantine keeps original permissions

### Evidence

`quarantine.add()` stores `metadata = {}`. `restore()` always writes 0600
(`O_EXCL | O_NOFOLLOW`, `dir_fd`; already matches ClamUI's GHSA-xhhj-qvvr-vhwq
hardening). A restored script loses its executable bit, and a shared file loses
group read.

### Fix

`quarantine.py` is exactly 400 lines, so the helpers go in a new
`oyst_core/quarantine_meta.py`.

1. **On add:** `fstat` the already-opened no-follow fd and store
   `{"mode": st_mode & 0o777, "uid", "gid", "size", "mtime"}`.
2. **On restore:**
   - `fchmod(dest_fd, stored_mode & 0o755)`: never setuid/setgid/sticky, never
     group/world-writable.
   - Legacy entries (`{}`) keep 0600.
   - Restore mtime with `os.utime(dest_fd)`.
   - No chown (unprivileged). If the stored uid ≠ the current uid, return a
     note "restored as your user".
   - **(Decision D3.)**
3. **GUI:** check that Restore and Delete already ask for confirmation. Add a
   confirm dialog if they don't (ClamUI v0.4.0 parity).

### Tests

- Round-trip of 0755 → 0755.
- 4755 → 0755.
- 0666 → 0644.
- Legacy entry → 0600.
- mtime is preserved.
- Security test: the mask can't be bypassed through tampered metadata. Values
  are validated as ints in range, otherwise 0600.

---

## R5 — cancel and timeout during a running scanner

### Evidence

- The stdout/stderr hang ClamUI fixed does **not** apply. `run_command` uses
  `subprocess.run(capture_output=True)`, which reads both pipes concurrently.
- Cancel is checked only *between* packs
  ([orchestrator.py:125,168](../../oyst_core/orchestrator.py)). A clamscan run
  (timeout 7200 s) can't be interrupted, so the GUI Cancel appears to do
  nothing for up to 2 h.
- On timeout, `subprocess.run` raises `TimeoutExpired`. `scan_paths` catches
  only `FileNotFoundError` / `OSError`, so the partial output is discarded and
  the exception reaches the orchestrator. How the orchestrator handles it still
  needs to be verified.

### Fix

1. Add `run_command_cancellable(argv, *, timeout, should_cancel, poll=1.0)` to
   `privileged/runner.py` (241 lines). It uses `Popen` and loops on
   `communicate(timeout=poll)`, keeping the same allowlist and env scrubbing as
   `run_command`.
   - On cancel or timeout: SIGTERM, wait 5 s, then SIGKILL; collect the
     remaining output.
   - Returns `CommandResult` plus a `stopped: "cancel" | "timeout" | None`
     field.
2. `ClamAVPack.scan` / `scan_paths` accept an optional `should_cancel`. The
   orchestrator passes `self.events.cancel_requested`.
   - Partial `FOUND` lines are parsed and kept.
   - Cancel → the orchestrator's existing `_cancel_result` with findings so far.
   - Timeout → `PartialScanError` with partial findings.
3. Scope: ClamAV only in this PR (the long-running one). Maldet follows the
   same pattern later.
4. Caveat: when clamscan is killed, its stdout may lose buffered lines, so
   partial results are best-effort. The UI says "Scan stopped — results may be
   incomplete".

### Tests

- A fake long-running process: cancel within ~1 s with partial output kept.
- Timeout → `PartialScanError` with findings.
- SIGKILL escalation.
- The allowlist is still enforced.

---

## Delivery order

1. **PR 1 — R1 + R2.** Fixes the broken backend; the advisory is small and
   touches the same doctor code.
2. **PR 2 — R3.** Stale signatures are the next-largest real-world risk.
3. **PR 3 — R5.**
4. **PR 4 — R4.**

Each PR runs `./scripts/check.sh` (LOC, ruff, mypy, pytest + security gates).
R1 and R3 are also checked by hand against ClamAV 1.5.4 on this host.

## Decisions needed

- **D1 — full mode + clamd.** `auto` prefers clamscan in full mode, so scans
  use oysterAV's own signatures and ignore list (recommended). The alternative
  is to allow clamd automatically and show a "uses host signatures" note.
- **D2 — update timer.** Auto-enable on full mode (recommended; user-level, no
  password) vs opt-in in Settings.
- **D3 — restore permissions.** Restore the original permissions, masked to
  ≤ 0755 (recommended), vs keep the always-0600 behaviour.

## Implementation notes (2026-10-11)

Two more bugs turned up during implementation and are fixed in the same change:

- **`parse_version` read only the major number** (`"1.5.4"` → `(1,)`), so every
  pack `min_version` check compared majors only (ClamAV 1.3 passed the 1.4.0
  floor). It now parses the full dotted version.
- **Lite mode + `clamav.ignore_sigs` broke every ClamAV scan.**
  `/var/lib/clamav` is clamav-owned, so writing `oysterav.ign2` raised
  PermissionError inside `scan()`. The write is now best-effort. `doctor`
  reports `ignore_sigs_note` when the list can't be applied.

New modules (to stay under the 400-line limit): `packs/clamd_client.py`,
`packs/clamav_version.py`, `signature_timer.py`, `quarantine_meta.py`.
R3 reuses the existing `freshclam-timer` service. In full mode it controls the
user timer `oyst-signatures.timer`, so the CLI, RPC and GUI switch work with
no new surface. `freshclam update` gained `--fangfrisch`.

Verified against real ClamAV 1.5.4, using a throwaway user-level clamd with a
one-line EICAR test signature:

- **Host-conf path:** inline-comment conf parsed, PING chose clamd,
  `--fdpass --multiscan` accepted, EICAR found, vault copy filtered.
- **Private-conf fallback:** 0600 conf containing only `LocalSocket`, EICAR
  found.
- **clamscan path:** works with `--exclude-dir`, and a real `/usr` scan was
  cancelled within 2 s.

`./scripts/check.sh --format` passes.

Not done: a lite-mode way to apply `ignore_sigs` to the host DB (would need a
privileged-helper recipe).
