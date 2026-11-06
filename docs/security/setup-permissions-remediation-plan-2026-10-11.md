# Setup wizard & permission paths — remediation plan (2026-10-11)

Source: findings-only review of the setup wizard, the root-side helper and
polkit policy, and userspace permission paths (RPC auth, Privilege Concert
callers, quarantine, runtime). This plan covers every finding from that review.

**Status: proposed — not implemented.** Decisions D1–D7 at the end need answers
before work starts.

Verification key: **Code** = re-read and confirmed in source; **Agent** =
reported by a review pass with file:line, not independently re-read;
**Plausible** = mechanism likely, needs a real-host check.

## Summary

| # | Item | Severity | Verified | PR |
|---|------|----------|----------|----|
| W1 | Wizard can disable / replace an already-active firewall | High | Code | 1 |
| W2 | "SSH-safe" assumes port 22; no sshd/zone detection; loose SSH parser | High | Code | 1 |
| W3 | UFW enable from inactive can't see its own SSH rule | Medium | Plausible | 1 |
| W4 | GTK widgets read inside worker threads | Medium | Code | 1 |
| H1 | Helper never checks where `oyst_core` actually imports from | High | Agent | 2 |
| H2 | `resolve_trusted_binary` follows symlinks, no dir check | High | Code | 2 |
| H3 | Embedded site root shadows stdlib; only `oyst_core/` vetted | Medium | Plausible | 2 |
| H4 | Elevated `oyst-cli` only partly vetted (incl. Flatpak path) | Medium | Plausible | 2 |
| H5 | VirusEvent wrapper target via `shutil.which` as root | Medium | Plausible | 2 |
| P1 | Full-mode Auto-Install: second polkit prompt (propupd) | High | Code | 3 |
| P2 | `TimeoutExpired` escapes `run_privileged*`; 5 s prompt timeout | Medium | Code | 3 |
| P3 | Polkit cancel (126/127) never classified; AUR→tarball re-prompts | Medium | Agent | 3 |
| P4 | Maintenance bootstrap via CLI/RPC prompts twice (rkhunter + lynis) | Low | Agent | 3 |
| P5 | `rkhunter --propupd` on every Update all / bootstrap | Medium | Code | 3 |
| S1 | Failed/denied concert still marks setup complete | Medium | Code | 4 |
| S2 | Harden Apply reports success after auth denied | Medium | Agent | 4 |
| S3 | Confirm dialog ≠ what actually runs (content + order) | Medium | Agent | 4 |
| S4 | Wizard doesn't preflight helper missing / outdated | Medium | Agent | 4 |
| S5 | `completed` reflects stored config, not this run | Low | Agent | 4 |
| S6 | `skip_packs` writes `skipped_steps=required_packs` implicitly | Low | Code | 4 |
| G1 | Actions can run concurrently (no global busy guard) | Medium | Agent | 5 |
| G2 | Window close (X) mid-run; callbacks hit destroyed widgets | Medium | Agent | 5 |
| R1 | `maldet-config` passwordless; denylist exact-match only; TOCTOU | Medium | Agent | 6 |
| R2 | clamonacc list files check-then-use as root | Low | Agent | 6 |
| R3 | `--socket=` path existence oracle | Low | Agent | 6 |
| R4 | SSH / linger-user safety rules enforced only in userspace | Low | Agent | 6 |
| R5 | Helper reads root's config instead of caller's | Low | Agent | 6 |
| R6 | Installer writes not nofollow/atomic | Low | Agent | 6 |
| R7 | Dead `run-sealed` action; uncaught `OSError`; legacy helper path | Info | Agent | 6 |
| U1 | `rkhunter.disable_tests` from config, no allowlist | Low | Agent | 7 |
| U2 | Grant / helper install show generic pkexec prompt | Low | Agent | 7 |
| U3 | Scheduled scans with privileged packs prompt unattended | Low | Agent | 7 |
| U4 | Stale-socket unlink race in `serve` | Low | Agent | 7 |
| U5 | Quarantine orphan regex can never match | Low | Code | 7 |
| C1 | CLI parity / hint / doc drift | Low | Agent | 7 |
| T1 | Security coverage gate misses key modules; no one-prompt tests | — | Code | 8 |

---

## PR 1 — Firewall safety in setup

### W1 — never silently stop or swap an active firewall

Evidence: [setup_wizard_firewall.py:95-103](../../oysterav/gui/widgets/setup_wizard_firewall.py)
selects from `rec` / saved preference only; index 0 (UFW) until
`firewall.recommend` returns. [setup_wizard_auto.py:111](../../oysterav/gui/widgets/setup_wizard_auto.py)
always sends `firewall_backend`, so [setup_harden_fw.py:38-46](../../oyst_core/setup_harden_fw.py)
takes the `--select-firewall` branch and never reaches `_resolve_ensure_target()`.
`none` maps to "disable everything" while the toggle label reads "Enable host
firewall (SSH-safe)".

Fix:
- Firewall page: preselect the **active** backend from `firewall.detect`
  (precedence: active > saved > recommended). Label the active one "(active)".
- Split intent: `firewall_backend` is only sent when the user picked a backend
  **different** from the active one on the Firewall page. Auto-Install / Harden
  "Enable firewall" with no explicit change → legacy `--with-firewall` (ensure
  the active/sole backend, SSH-safe).
- "Keep host as-is" → send nothing (no firewall flag). Disabling all firewalls is
  not offered from the wizard (D1); it stays CLI-only (`firewall select none`).
- Disable Auto-Install and Harden Apply until the firewall page data has loaded
  (or snapshot "unknown" → no firewall flag).
- When a swap *is* requested, the disclosure lists "Stop firewalld", "Install
  ufw" (if missing), "Enable ufw" as separate lines (ties into S3).

### W2 — real SSH detection

Evidence: [helper_fw_enable.py:56,88](../../oyst_core/privileged/helper_fw_enable.py)
hardcode `22/tcp` and `zone=public`; [firewall_ops.py:389-398](../../oyst_core/packs/firewall_ops.py)
`\b22\b` matches `10.0.0.22`, `22/udp`, `ALLOW OUT`.

Fix (root side, new module `oyst_core/privileged/helper_ssh_ports.py`):
- `detect_sshd_ports()`: `sshd -T` (via `resolve_trusted_argv`) → `port` lines
  plus `listenaddress`; fall back to `ss -Htlnp` filtered to the `sshd` process;
  also include socket-activated `ssh.socket` `ListenStream`. Returns a set of
  ints, or `None` on detection failure.
- `ssh_session_active()`: from userspace, pass `--ssh-session` when
  `SSH_CONNECTION`/`SSH_CLIENT` is set in the serve/CLI environment (the
  helper's env is scrubbed). Root side additionally checks `who`/`loginctl`
  remote sessions.
- Failure policy (D2): if ports can't be detected **and** sshd is running or a
  remote session exists → refuse enable (soft-fail, clear message). If sshd is
  not installed/running and no remote session → proceed without an SSH rule.
- UFW: `allow <port>/tcp` for each detected port (v4+v6 handled by ufw).
- firewalld: zone = `--get-default-zone` and every zone from
  `--get-active-zones`; `--add-port=<p>/tcp` (or `--add-service=ssh` when the
  only port is 22). Verify with `--zone=<z> --query-port`.
- Replace `parse_ssh_open` with a structural parser per backend: UFW rules
  parsed as `(to, action, direction, from)`; require `ALLOW|LIMIT`, `IN`,
  `from Anywhere`, `to` matching `<port>(/tcp)?` — no substring on IPs.
- Fix the bogus `--force-lockout-risk` hint in user-facing messages (C1) — say
  "Use `oyst-cli firewall plan` to review rules" instead, or add the flag to
  `setup run` (D-none; recommend: drop the hint; GUI never forces).

### W3 — UFW verification while inactive

Fix: after `ufw allow`, verify with `ufw show added` (lists pending rules while
inactive) using the structural parser; fall back to trusting the allow
command's rc==0. After `ufw enable`, re-verify with `ufw status verbose`; on
miss → `ufw disable`, soft-fail (mirrors the firewalld rollback).

Real-host check required (Manjaro test host: install ufw in a VM/container).

### W4 — snapshot GUI state on the main thread

Fix: in `setup_wizard_auto.py` and `setup_wizard_harden.py`, compute
`backend = selected_firewall_backend(wizard)` and
`enabled_harden_step_ids(...)` **before** `run_in_thread`; worker closes over
plain values. Same snapshot feeds the disclosure (S3), so what is confirmed is
what runs.

### Tests
- `tests/test_core/test_helper_ssh_ports.py` (security): `sshd -T` with 2222,
  multiple ports, ListenAddress v6, detection failure + sshd running → refuse.
- Structural parser: `10.0.0.22`, `22/udp`, `ALLOW OUT`, `from 1.2.3.4` → not open.
- `ensure_ufw` inactive path uses `show added`; post-enable miss → disable.
- `ensure_firewalld` uses default + active zones.
- `setup_harden_fw`: no backend + with_firewall → ensure; explicit backend equal
  to active → ensure, not select.
- GUI unit (rpc_actions-style, no display): wizard sends no `firewall_backend`
  when selection == active / "Keep host as-is".

---

## PR 2 — Helper code & binary trust

### H1 / H3 — runtime import self-check

Evidence: [install_privileged_helper.py:308-309](../../oyst_core/privileged/install_privileged_helper.py)
writes a plain helper when system python imports `oyst_core`, with no check of
the resolved location; [helper_site_trust.py:84-86](../../oyst_core/privileged/helper_site_trust.py)
returns None when there's no `sys.path.insert` to parse. Editable installs via
system `.pth` survive `-I`.

Fix:
- New `oyst_core/privileged/helper_selfcheck.py`, called first thing in
  `oyst_helper.main()`: resolve `Path(oyst_core.__file__).parent`, run
  `untrusted_site_reason()` on it (ancestors uid 0 + no 0o022; tree lstat, no
  symlinks). Also check every loaded module's `__file__` that lives outside
  the stdlib prefix (`sysconfig.get_paths()["stdlib"]`/`platstdlib`) — catches
  H3 shadowing and third-party deps (pydantic etc.) from user-writable dirs.
- Refuse (exit 2, "helper code is not root-locked") unless the helper was
  installed with `--dev` (D7), which embeds `OYST_HELPER_DEV=1` as a constant
  in the generated script; dev helpers keep refusing the grant (unchanged).
- Install/grant time: run `python -I -c 'import oyst_core;print(oyst_core.__file__)'`
  with `cwd=/` and feed the result to `untrusted_site_reason`.
- H3: change the generated script to `sys.path.append(site_root)` **and**
  require site_root to contain only `oyst_core` + vetted deps, or switch to a
  dedicated `/usr/lib/oysterav/site/` containing only `oyst_core` (recommend:
  `append` + full-tree check via self-check above).

### H2 — trusted binary resolution

Evidence: [helper_validate.py:60-78](../../oyst_core/privileged/helper_validate.py)
`is_file()`/`stat()` follow symlinks; then `resolve()`.

Fix: `helper_validate.py` is 342 lines → move binary resolution into new
`oyst_core/privileged/trusted_bin.py`:
- `lstat` candidate; if symlink, `resolve(strict=True)` and require the
  **target** to be under `_TRUSTED_BIN_DIRS` (covers `/bin → /usr/bin` merged-usr).
- Require the target file *and every ancestor directory* of both candidate and
  target to be uid 0 and not group/world-writable (0o022). This rejects
  `root:staff 2775 /usr/local/bin` — acceptable; log which dir failed.
- Return the resolved target path. Apply the same helper to
  `_is_root_owned_system_bin` ([install_privileged_helper.py:76-85](../../oyst_core/privileged/install_privileged_helper.py))
  and `schedule_linger._is_root_owned_system_bin`.

### H4 — vet the `oyst-cli` we elevate

Evidence: [elevate_cli.py:108-119](../../oyst_core/privileged/elevate_cli.py),
[schedule_linger.py:19-27](../../oyst_core/schedule_linger.py); Flatpak path
[elevate_cli.py:72-77](../../oyst_core/privileged/elevate_cli.py) unchecked.

Fix: before `pkexec <oyst-cli> …`, require: script passes `trusted_bin`; its
shebang interpreter passes `trusted_bin`; `<interp> -I -c 'import oyst_core;…'`
location passes `untrusted_site_reason`. Flatpak: run the same probe via
`flatpak-spawn --host` and refuse on failure. Cache the verdict per
(path, mtime, inode) for the serve process lifetime.

### H5 — VirusEvent wrapper target

Evidence: [virusevent.py:27-35](../../oyst_core/virusevent.py).

Fix: wrapper target = `resolve_oyst_cli_path(for_elevation=True)` (H4 checks);
no `shutil.which`. If none → skip writing the wrapper, `virusevent ensure`
reports "requires a system-installed oyst-cli".

### Tests (all `-m security`)
- Self-check: fake `__file__` under a 0o777 tmp dir → refuse; dev constant → allow.
- `trusted_bin`: symlink in trusted dir → target outside trusted → reject;
  group-writable dir → reject; merged-usr `/bin` symlink → accept.
- Elevation vetting: user-writable site root → refuse before pkexec runs
  (assert `run_install_command` not called).
- VirusEvent: no system oyst-cli → no wrapper written.

---

## PR 3 — One prompt per action; cancel & timeout

### P1 — full-mode propupd outside the concert

Evidence: [runtime_full_bootstrap.py:73](../../oyst_core/runtime_full_bootstrap.py)
calls `run_bootstrap(skip_lynis=…)` without `skip_rkhunter_propupd`;
[setup_workflow.py:197](../../oyst_core/setup_workflow.py) excludes propupd
from the concert in full mode.

Fix: add `skip_rkhunter_propupd` param to `run_full_runtime_bootstrap`; setup
passes `True` and always includes `--propupd` in the concert argv when wanted
(subject to P5 policy). Same for "Install runtime and update signatures" /
"Maintenance only" wizard buttons — route their propupd through one concert.

### P2 — timeouts

Evidence: [runner.py:170-192](../../oyst_core/privileged/runner.py) `subprocess.run(timeout=…)`;
[helper.py:62,81,102](../../oyst_core/privileged/helper.py) catch only
`ValueError, OSError`; [clamonacc.py:190](../../oyst_core/packs/clamonacc.py) `timeout=5`.

Fix:
- Catch `subprocess.TimeoutExpired` in all three `run_privileged*` wrappers →
  `CommandResult(124, "", "timed out")` and a `timed_out` flag on the result.
- Minimum timeout for pkexec-wrapped calls: `max(timeout, 300)` so the auth
  prompt isn't cut off; clamonacc start becomes a helper call that returns
  after spawn (it's already `--foreground`-capable; use `systemd-run --unit`
  via the helper, or raise timeout to the floor).
- Note: a post-auth kill can't signal a root child; on timeout report
  "may have completed — refresh status" rather than "failed".

### P3 — cancel classification

Fix:
- `privilege/run.py`: map pkexec rc 126 (dismissed/not authorized) and 127
  (auth failure / no agent) to a step `{"step": recipe, "ok": False,
  "cancelled": True}` and a top-level `auth_cancelled` result field.
- All concert callers (setup, scan, update, resolve, bulk install) stop further
  privileged work on `auth_cancelled` and surface "Authentication was cancelled"
  (plain language).
- [pack_install.py:231-232](../../oyst_core/pack_install.py): only fall back to
  the tarball when the AUR failure is not an auth denial; AUR path itself stays
  opt-in (`confirm_aur`) and is disclosed as "uses your AUR helper's own sudo
  prompt" (D4).

### P4 — bootstrap double prompt

Fix: `run_bootstrap` builds one `setup-harden`-style concert (`--propupd`,
`--lynis-audit`) instead of two `run` calls; RPC default `skip_lynis` stays but
both privileged ops share the one prompt.

### P5 — propupd policy

Evidence: [updates.py:95,122](../../oyst_core/updates.py)
`include_rkh_propupd=rkh_installed`; `maintenance.py:57-63,95-98`.

Fix (D3): include propupd only when (a) at least one host package was upgraded
in this update run, and (b) the latest rkhunter result has no open warnings.
Otherwise skip with a visible note ("Baseline not refreshed: open rkhunter
warnings"). First-time setup keeps propupd (no baseline exists yet).

### Tests
- One-prompt counter fixture: patch `run_privileged_helper`/`run_privileged`
  and assert exactly one call for: setup full mode, setup lite, Update all,
  bootstrap (CLI default), bulk resolve, multi-pack scan.
- Timeout → `CommandResult(124)`, no exception escapes to RPC.
- rc 126 → `auth_cancelled`, later steps not attempted, no tarball fallback.
- propupd gating: no upgrades → excluded; open warnings → excluded + note.

---

## PR 4 — Truthful wizard status & disclosure

### S1 / S5 — completion

Evidence: [privilege/run.py:71-73](../../oyst_core/privilege/run.py) returns a
single `recipe` step with `soft_fail`; `"setup"` isn't in `_BLOCKS_COMPLETE`
([setup_workflow.py:37](../../oyst_core/setup_workflow.py)).

Fix: if the concert returns no parsed steps (or `auth_cancelled`), synthesize a
failed step for **every** requested privileged step id (harden-*, firewall-*,
linger, install-packs) with the same message, so `_BLOCKS_COMPLETE` applies.
Result exposes `marked_complete` for this run; GUI uses it instead of
`completed` (`setup_workflow.py:332`).

### S2 — Harden Apply status

Fix: [setup_wizard_harden.py:74-88](../../oysterav/gui/widgets/setup_wizard_harden.py)
includes the concert/cancel step; `_harden_ran` only when ≥1 privileged step
returned `ok` and not `skipped`. `_apply_ran_flags` same rule.

### S3 — disclosure derived from argv

Fix: build the concert plan first (`build_concert_argv` with the snapshotted
inputs from W4), then derive disclosure lines from the plan's flags using the
existing priority order (`privilege/priority.py`). GUI requests the plan via a
new read-only RPC `setup.plan` (CLI: `oyst-cli setup run --dry-run --json`, which
already prints a disclosure — make both use the same function). Order shown =
helper execution order. Include bootstrap/signatures, propupd, package
installs, firewall stop/swap.

### S4 — helper preflight

Fix: before the Auto-Install confirm dialog, call `helper.status`; if missing
or `policy_current=False`, show "Install / update the privileged helper first"
with the existing `helper.install` action, and keep Auto-Install disabled until
it succeeds (the helper install is its own user action with its own prompt).

### S6 — skipped_steps

Fix: only write `setup.skipped_steps=required_packs` from the explicit
"Continue anyway" path; Finish / Harden Apply pass a new `record_skip=False`.

### Tests
- Concert rc 126 with no stdout → setup not marked complete; GUI result shows
  cancelled.
- `setup.plan` lines == flags in argv, same order, for full and lite modes.
- Harden Apply with denied auth → `_harden_ran` False.

---

## PR 5 — Wizard GUI robustness

### G1 — one busy guard

Fix: `wizard._busy` (single flag) set by every mutating action (Auto-Install,
Harden Apply, per-item Ensure, Apply firewall choice, runtime/maintenance
buttons, Review packs navigation). A `_set_busy()` helper toggles sensitivity
of all action buttons. DisableCache Ensure gets a confirm dialog like the
other Ensure buttons.

### G2 — close-request

Fix: connect `close-request` in `setup_wizard.py`; while busy → return `True`
(block) and show a toast "Setup is still running"; when idle → route through
`finish_setup(mark_complete=False)`. `done` callbacks check a `_destroyed` flag.

### Tests
- GUI-skipped-without-display widget test: busy → close returns True.
- Pure-logic test of `_set_busy` sensitivity map (no display needed).

---

## PR 6 — Root-side scope hardening

- **R1 maldet-config:** passwordless (grant) path accepts only `users` or paths
  under the caller's home (`PKEXEC_UID` → pwd home); other paths require a
  separate non-grant polkit action (`auth_admin`). Write the **resolved** path;
  re-resolve with `O_NOFOLLOW` walk at write time. Denylist becomes prefix-based
  for `/etc /usr /var /boot /proc /sys /dev /root` and other users' homes.
- **R2 clamonacc lists:** copy validated list into `/run/oysterav/clamonacc/<uid>.list`
  (root 0600, nofollow write) and pass that path.
- **R3 socket:** allowlist `--socket=` to `/run/clamav/`, `/var/run/clamav/`,
  `/run/clamd.scan/` prefixes before any `exists()`.
- **R4 helper-side rules:** apply `rich_rule_ssh_lockout_risk` + W2 port set to
  `ufw deny/reject <ssh port>`, `default deny incoming`, and `enable` inside
  `helper_firewall*.py`; `--linger-user` and `run loginctl` must equal the
  `PKEXEC_UID` username; rkhunter whitelist paths require a package-owned check
  root-side (pacman -Qo / dpkg -S / rpm -qf via trusted_bin) unless `--force`
  was disclosed.
- **R5 config:** pass `--managed-backend=ufw|firewalld|none` from userspace;
  helper stops reading `get_config_value` ([helper_fw_lifecycle.py:107-116](../../oyst_core/privileged/helper_fw_lifecycle.py)).
- **R6 installer writes:** `write_text_nofollow(..., mode=0o755/0o644)` + chown 0:0
  at [install_privileged_helper.py:352-356,375](../../oyst_core/privileged/install_privileged_helper.py).
- **R7:** remove `run-sealed` from `polkit_policy.py` and the shipped policy
  (bump `POLICY_VERSION`; S4 then prompts reinstall); catch `OSError`/`ValueError`
  in `oyst_helper.py:188-192` → exit 2 with message; `helper.py:256` stop
  considering the legacy `/usr/local/lib/oysterav/oyst-helper` (status reports
  "legacy helper found — reinstall").

### Tests
Per item, all `-m security`; R4: `ufw deny 22` via helper with sshd on 22 →
refused; `--linger-user=root` from uid 1000 → refused.

---

## PR 7 — Userspace low items & drift

- **U1:** allowlist of disable-able rkhunter tests (current defaults set);
  preflight lists the test names.
- **U2:** dedicated polkit actions `…oysterav.helper-install` and
  `…oysterav.grant-lifecycle` with explicit messages ("Allow oysterAV to
  start/stop its security services without a password for 7 days"). Requires
  H4 elevated-cli path to call through these actions.
- **U3 (D6):** schedules containing privileged packs: skip those packs at run
  time with a history note "needs authentication — run manually", never prompt
  from a timer.
- **U4:** `flock` on `<data dir>/serve.lock` around check/unlink/bind; `lstat`
  + `S_ISSOCK` before unlink; refuse non-socket.
- **U5:** fix `_ORPHAN_NAME_RE` to `^\d{14}_[0-9a-f]{32}\.bin$` (keep old
  pattern as alternative for legacy names) — [quarantine.py:356](../../oyst_core/quarantine.py).
- **C1:** add `--harden-include` to `setup run`; CLI saves
  `firewall.managed_backend` like the GUI (move the save into `setup_workflow`
  so both share it); copy-hints include `--confirm` and use
  `--no-mark-complete` for harden; fix `gui-contract.md:294,450` and the fdpass
  subtitle text.

---

## PR 8 — Test gates

- Add to `SECURITY_MODULES` in [check_security_coverage.py](../../scripts/check_security_coverage.py):
  `privileged/helper.py`, `privileged/elevate_cli.py`, `privileged/runner.py`,
  `privileged/trusted_bin.py`, `privileged/helper_selfcheck.py`,
  `privileged/helper_ssh_ports.py`, `privileged/helper_fw_enable.py`,
  `setup_concert.py`, `setup_harden_fw.py`, `quarantine.py`, `serve.py`.
- Mark existing elevate / scanner_exec / quarantine tests `security`.
- The one-prompt counter fixture (PR 3) lives in `tests/conftest.py` for reuse.
- Land this last so the ≥85% gate is met by the tests added in PRs 1–7.

## Delivery order

1. **PR 1** firewall safety — highest user-visible risk (remote lockout,
   dropped services).
2. **PR 2** helper trust — highest privilege risk (needs specific setups).
3. **PR 3** prompts / cancel / timeout — Privilege Concert compliance.
4. **PR 4** truthful status — depends on PR 3's `auth_cancelled`.
5. **PR 5** GUI robustness.
6. **PR 6** root-side scope (includes policy bump; ship after PR 4's S4 so the
   wizard prompts reinstall).
7. **PR 7** low items. **PR 8** gates.

Each PR: `./scripts/check.sh` green; 400-line limit respected via the new
modules named above (`setup_workflow.py` and `helper_validate.py` are both at
342). Release notes call out the policy bump (PR 6) and helper reinstall.

## Decisions needed

- **D1** — Remove "disable all firewalls" (`none`) from the wizard and keep it
  CLI-only? *Recommend: yes.*
- **D2** — When sshd port detection fails and sshd is running / a remote
  session exists: refuse enable (recommend) or fall back to 22?
- **D3** — propupd policy: gate on "packages upgraded + no open warnings"
  (recommend) vs. make it always explicit opt-in.
- **D4** — AUR maldet path: keep as opt-in with disclosed separate sudo prompt
  (recommend), or drop AUR and always use the pinned tarball via the helper
  (fully one-prompt)?
- **D5** — Keep `auth_admin_keep` on `systemctl-up` / `maldet-config`?
  *Recommend: change to `auth_admin`; the grant already covers the
  passwordless case.*
- **D6** — Scheduled scans with privileged packs: skip with note (recommend)
  vs. reject at schedule-creation time.
- **D7** — Dev-installed helpers: keep allowing them to run user-writable code
  for `auth_admin` actions (recommend, with a persistent "development helper"
  warning in `doctor`), or refuse unless an env flag is set at runtime?
