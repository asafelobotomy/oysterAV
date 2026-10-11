# oysterAV — Full-Surface Audit

- **Repo:** https://github.com/asafelobotomy/oysterAV @ `16d5e33` (v0.2.2)
- **Date:** 2026-10-11
- **Method:** static review of every surface (privilege boundary, RPC, supply chain, scan/quarantine/data, CLI/GUI, packaging/CI/docs) plus the project's own gate suite (`scripts/check.sh`). Nothing ran as root. No scanners or installers ran.
- **Severity:** these are my ratings. Polkit actions are `auth_admin` unless noted, so most root-level issues need either an admin approving a misleading prompt or the passwordless grant. All of them turn a user-level compromise into root.
- **Verified** = I re-checked it in the code or by running it myself. **Plausible** = a sound reading of the code that has not been exercised.

---

## 1. Gate suite results

| Gate | Result |
|---|---|
| version sync, LOC ≤400, ruff check, ruff format, mypy (245 files) | ✅ pass |
| pytest (with `--extra all`) | ❌ **1 failed**, 1150 passed, 1 skipped. Coverage 66.8% (floor is 65%) |
| security marker suite | ❌ same flaky failure (≈50% of runs) |
| security-module coverage | ✅ 87% |
| bandit | ⚠️ "passes", but **2 files are skipped** with a syntax error (see G2) |
| pip-audit | ⚠️ "passes", but it **audits its own tool venv, not the project** (see G3). I re-ran it against the `uv.lock` export: no known vulns |

- **G1. Flaky DoS test.** `tests/test_security/test_rpc_dos_bounds.py::test_accept_semaphore_rejects_ninth_connection`.
  - It fails about half the time with `BlockingIOError` on connect (`listen(5)` backlog < 9 connections) and `ValueError: Semaphore released too many times`.
  - Cause: the retry loop force-refills the module-global `BoundedSemaphore` while threads from earlier attempts are still alive. Earlier `serve_forever` threads are never stopped either.
- **G2. Bandit silently skips files.** `uv tool run bandit` resolves to Python 3.11, which cannot parse PEP 695 syntax. That skips `oyst_cli/options.py` and `oyst_core/runtime/progress.py` while the gate still reports success.
  - Fix: `uv tool run --python 3.12 bandit`, and fail on skipped files.
- **G3. pip-audit gate is a no-op.** `uv tool run pip-audit` with no args audits the ephemeral tool environment (CacheControl, cyclonedx, …). It never sees oysterAV's dependencies.
  - Fix: `uv export --frozen --all-extras --no-emit-project | pip-audit -r /dev/stdin --no-deps --disable-pip`.
- **G4. GUI tests error instead of skipping without `gi`.**
  - 11 modules fail at collection: `oysterav/gui/__init__.py` eagerly imports `app` → `gi`.
  - The skip hook in `conftest.py` runs after collection, so it can't help. This contradicts AGENTS.md ("GUI-dependent tests are skipped"), and plain `--extra dev` aborts the whole suite.
  - Fix: `pytest.importorskip("gi")` in those modules, or a lazy `gui/__init__`.

---

## 2. Critical / High

### Privilege boundary

**P1 — fail2ban config newline injection → root config write (likely root RCE)** — High — *Verified*
- **Where:** `oyst_core/privileged/validators.py:49` → `helper_fail2ban.py:42`.
- **Cause:** `validate_ip` is `str(ipaddress.ip_address(v.strip()))`. IPv6 scope IDs accept nearly any character, and the call returns the input unchanged. I confirmed this by running it: `validate_ip("fe80::1%x\nignorecommand = id")` passes.
- **Effect:** the value is written verbatim as `ignoreip = …` into `/etc/fail2ban/jail.d/oysterav-<jail>-ignore.conf`, followed by `fail2ban-client reload`.
- **Impact:** at minimum it can silently disable or weaken jails (`enabled = false`). Via `ignorecommand` it plausibly runs a command as root.
- **Fix:**
  - Reject `%` and any character outside `[0-9a-fA-F:.]`.
  - Write the validated `ip_address` object without its scope.
  - Add a corpus test for this input.

**P2 — "Sealed" scanner runs a user-writable binary as root with a caller-supplied hash** — High — *Verified*
- **Where:** `privileged/scanner_exec.py:74-80`, `helper_sealed_scanner.py:21-110`.
- **Cause:** the unprivileged side hashes `~/.local/share/oysterav/runtime/.../rkhunter` and passes that hash in argv. Root only checks that the file matches the hash it was handed. The `_RUNTIME_PATH_RE` pattern starts with `^.*/`, so `/tmp/x/.local/share/oysterav/runtime/a/rkhunter` also qualifies.
- **Impact:** user-level malware swaps the binary, and the next authenticated scan runs it as root behind a "hash-verified copy" prompt.
- **Fix:** keep the pinned digests in a root-owned manifest and ignore argv. Or refuse runtime binaries for privileged runs.

**P3 — `install-script` runs any tarball's `install.sh` as root, same pattern** — High — *Verified*
- **Where:** `helper_install_script.py:46-125`.
- **Cause:** the digest comes from argv. `MALDET_SHA256` is pinned only in userspace (`pack_sources.py:23`). Any user can create `/tmp/oyst-maldet-*/`.
- **Fix:** hard-code the allowed digest in the helper.

**P4 — `--dev` helper + passwordless grant = root with no prompt** — High — *Plausible (code-verified chain)*
- **Where:** `install_privileged_helper.py:155-173,202,243`, `auth_grant_expire.py:36-52`.
- **Cause:** a dev install embeds `sys.path.insert(0, <user checkout>)` into `/usr/lib/oysterav/oyst-helper` and into the root expire script. `systemctl-up` can be made `YES`.
- **Impact:** editing any helper module in the checkout, then `pkexec … systemctl-up start clamav-daemon`, runs that code as root silently.
- **Fix:** refuse the grant (and the re-grant on install) when the helper has a non-root site root, and never copy the insert into the expire script.

### Scan correctness (missed or false "clean" results)

**S1 — Denied or failed privileged scan is reported as clean, exit 0** — High — *Verified*
- **Where:** `orchestrator_scan_concert.py:27-35`, `privilege/run.py:71-73`.
- **Cause:** on pkexec cancel or helper failure the only step is `{"step":"scan-privileged","ok":False}`. That maps to pack `"privileged"`, which is not in `PRIVILEGED_SCAN_PACKS`, so `continue` drops it.
- **Impact:** rkhunter, chkrootkit, unhide and lynis never ran, yet the result is `clean=True` and history shows "Clean".
- **Fix:** convert any `ok=False` step into a `PackError` for every requested pack, and flag requested packs that have no report.

**S2 — clamscan exit code 2 and decode errors are ignored** — High — *Verified (logic)*
- **Where:** `packs/clamav.py:259-296`, `privileged/runner.py:202`, `models.py:117`.
- **Exit code:** `parse_findings` never looks at `returncode`, so a database load failure or I/O error reads as "clean".
- **Decoding:** `text=True` uses strict UTF-8. clamscan runs without `-i`, so one non-UTF-8 filename raises `UnicodeDecodeError` and loses every finding.
- **Clean flag:** `ScanResult.clean` ignores `pack_errors`.
- **Fix:** treat rc ≥ 2 as an error, decode with `surrogateescape`, pass `-i`, and make the result non-clean when any pack errored.

**S3 — FOUND-line parsing quarantines the wrong file** — High — *Verified*
- **Where:** `packs/clamav.py:262`.
- **Cause:** `line.split(":", 2)` splits on the first colon, and `"FOUND" in line` matches anywhere in the line.
- **Example:** `report.pdf:x.exe: Trojan FOUND` quarantines (unlinks) the innocent `report.pdf` and leaves the malware.
- **Other cases:** `NOT_FOUND.txt: OK` is treated as a hit. Newlines in filenames forge lines.
- **Fix:** require the line to end with ` FOUND`, use `rsplit(": ", 1)`, and reject control characters.

**S4 — Quarantine `add()` unlinks a re-resolved path, not the opened inode (TOCTOU)** — High — *Plausible (code-verified)*
- **Where:** `quarantine.py:85-157`.
- **Cause:** `O_NOFOLLOW` covers only the last path component. The code hashes the fd, then calls `src.resolve()` and `unlink()` on the result.
- **Impact:** a parent directory swapped for a symlink makes it delete a victim file. This becomes root-level deletion if VirusEvent runs as root.
- **Fix:** use `openat`/`unlinkat` relative to a parent directory fd opened `O_NOFOLLOW`, and compare `st_dev`/`st_ino` before unlinking.

### CI / packaging

**C1 — Flatpak is effectively unsandboxed** — High — *Verified*
- **Where:** `--filesystem=host` plus `--talk-name=org.freedesktop.Flatpak` in both manifests, which allows `flatpak-spawn --host`. The metainfo doesn't disclose this.
- **Fix:** disclose it prominently, or make the Flatpak a pure RPC client of the host `oyst-cli serve`.

**C2 — fpm `.deb`/`.rpm` likely non-portable** — High — *Plausible*
- **Cause:** `uv pip install --prefix` uses the CI venv's interpreter. The likely results are venv shebangs, `site-packages` instead of `dist-packages`, and bundled dependencies.
- **Testing gap:** the smoke test never installs the package and runs it.
- **Fix:** build a wheel, install it with `installer --destdir` using the distro Python, and add a container install smoke test.

---

## 3. Medium

### Privilege
- **Expired passwordless grants resurrect.**
  - `migrate_grant_on_helper_install` re-grants with a fresh 7-day TTL even when the stamp has expired.
  - The expiry timer uses `OnActiveSec` + `Persistent=true`, so it resets each boot and never fires on machines that reboot within 7 days.
  - Files: `auth_grant.py:320-337`, `auth_grant_expire.py:92-103`.
- **Site-root trust checks only one directory** (`install_privileged_helper.py:127-152`). Ancestors and the package tree are unchecked, and `sys.path.insert(0)` lets modules there shadow the stdlib.
- **Scan-report directory permissions** (`helper_scan_concert.py:60-66`).
  - The report root is `0750 root:root`, but the user reads reports from there. Every privileged scan likely fails with "cannot read report", which compounds S1.
  - The later `chown`/`chmod` follow symlinks; use `fchown`/`fchmod`.
- **Arch partial upgrades.** `pacman -Sy --noconfirm <pkg>` in `helper.py:110`, `helper_setup_concert.py:32`, `helper_update_concert.py:276`, `helper_fw_lifecycle.py:72`. This is unsupported on Arch and can break the host.

### Supply chain
- **AUR upgrades use `--noconfirm`** (`updates.py:136,179-194`). "Update all" upgrades chkrootkit, maldet and fangfrisch without PKGBUILD review, unlike the initial install, which requires `confirm_aur`.
- **fangfrisch venv is installed without hash pinning** (`fangfrisch_bundle.py:30-37`). Its transitive dependencies are resolved live.
- **Fedora updates are never detected** (`updates_query.py:401-418`). `dnf check-update` names carry an arch suffix (`clamav.x86_64`), so they never match the tracked names.
- **One bad news feed aborts all feeds** (`security_news_fetch.py:223-228`). `ParseError` is a `SyntaxError` and is not caught.

### RPC / jobs
- **Job lock race** (`events_jobs.py:44-62`). A SELECT followed by an unconditional UPDATE means the timer scan and the GUI scan can both acquire the lock. *Verified.*
  - Fix: `UPDATE … WHERE job_id IS NULL` and check `rowcount`.
- **Cancel corrupts job state.**
  - Double-cancel force-releases the lock of a live job.
  - `release_job_lock` clears the cancel flag even when the caller isn't the owner.
  - The 2 h stale timeout is shorter than or equal to the 7200 s scan timeout.
  - Files: `orchestrator_helpers.py:149-156`, `events_jobs.py:109-182`.
- **8-slot connection pool** (`serve.py`). The timeout is per `recv`, not per frame (slowloris). Long methods hold slots for up to 2 h. Overflow connections are closed silently. `accept()` errors kill the server, and `stop()` has no effect.

### Scan / data
- **Exclude dirs are unanchored regexes** (`scan_excludes.py`, `clamav.py:223`). Excluding `/opt` also skips `~/Downloads/options/`. Relative entries like `.` exclude everything.
  - Fix: require absolute paths and emit `^re.escape(p)(/|$)`.
- **Quarantine guards key on basename or path component anywhere.** A file named `~/Downloads/clamscan`, or anything under `…/maldetect/sigs/`, is never quarantined.
- **Long filenames (>~231 bytes) can't be quarantined.** They hit ENAMETOOLONG, and the error is swallowed.
- **Phantom quarantine rows.** The DB row is committed before the unlink, so a failed unlink leaves an orphan row.
- **VirusEvent strips filename whitespace** (`virusevent.py:203`).

### GUI / CLI
- **GUI is the backend** (`app.py:76`, `serve.py:53`, `client.py:31-38,103-183`).
  - The RPC server runs as a thread inside the GTK process.
  - The silent in-process fallback skips auth.
  - Progress-enabled installs bypass RPC (and its audit logging) entirely.
  - Together these contradict ADR-002 and gui-contract ("elevation not in the GTK process"). Quitting the GUI kills running jobs without warning.
- **Pango markup injection.**
  - The GUI never calls `markup_escape_text`, but `Adw.ActionRow` title/subtitle and `Adw.Banner` parse markup by default.
  - Paths, audit messages, exception text and similar values are interpolated straight in (e.g. `settings_host_audit_ui.py:54`).
  - Effect: rows go blank on `&`/`<`, and crafted directory names can spoof the displayed text.
  - (The supply-chain review called markup safe because it looked only at `Gtk.Label.set_text`; the Adw rows are the gap.)
- **Firewall rule removal can delete a different rule** (`shield_firewall_rules_ui.py:115-168`, `firewall_cmd.py:171-205`). Direction, v6 and `from` are dropped. Removing "22/tcp ALLOW from 192.0.2.0/24" targets the unrestricted `allow 22/tcp` rule, an SSH lockout risk.
- **Blocking calls on the GTK main loop.** Examples: `job_status` every 400 ms with a 30 s timeout, `setup_reset` → `doctor_all`, and wizard `setup_status`/`setup_run`.
- **"Run setup wizard" wipes setup state before the wizard opens.** Cancelling then re-prompts on every launch.
- **CLI `quarantine restore/delete` traceback on errors** (`oyst_cli/.../quarantine.py:74,103`). There is no JSON output, and the command exits 1, which collides with "threats found".

### CI
- **Script injection** (`release.yml:51`). `"${{ inputs.version }}"` is interpolated into `run:` in a job that holds `contents: write`. *Verified.*
  - Fix: pass it via `env:` and validate against a semver regex.
- **Workflow-wide `contents: write`** with `persist-credentials` left at its default, while build jobs pull unpinned PyPI/RubyGems/Flathub content. There is no release environment gate.
- **Force republish** builds `github.sha` from any dispatched branch and overwrites the release assets with `make_latest`.
- **Release artifacts are not reproducible or signed.** The Flatpak dir build and fpm ignore `uv.lock`. `gem install fpm` and the `semgrep/semgrep` image are unpinned. There are no SHA256SUMS or attestations.
- **PyPI auto-publish never fires.** A release created with `GITHUB_TOKEN` doesn't trigger `release: published`.

---

## 4. Low / Info (abridged)

### Privilege
- The rich-rule SSH-lockout guard is a substring check, bypassable with `port=022` or a tab.
- `ensure-fdpass --unit=` accepts any allowlisted unit, e.g. it can write a fail2ban drop-in that runs clamonacc.
- fail2ban persist overwrites the previous IP. Jail `DEFAULT` replaces the global `ignoreip`.
- clamonacc `--include-list=` lets root read any non-group-writable file, e.g. `/etc/shadow`.
- The OnAccess deny-list is missing `/bin`, `/lib`, `/lib64`, `/snap` and `/nix`.
- `maldet-config` accepts any absolute path, under the passwordless scope.
- `write_text_nofollow` is non-atomic: `O_TRUNC` happens before the type check, and a FIFO blocks the open.
- Harden reprobe uses unit `clamd`, which the validator rejects.

### RPC
- A non-ASCII token makes `compare_digest` raise TypeError, which surfaces as `internal_error` with a traceback.
- `RecursionError` on deeply nested JSON is not caught.
- A new server unlinks a live socket.
- Handlers return `internal_error` for bad params.
- `fail2ban.jail` skips `validate_jail`.
- Token-creation race.
- `history.list`/`audit.list` accept an unbounded `limit`.
- Raw params are logged.

### Supply chain
- Downloads are unbounded in size.
- Redirects to HTTP or other hosts are allowed.
- News item links are opened without a scheme check (`file:`, `smb:`).
- Feed titles may carry C1 control characters into the terminal.
- The `maldetect-current.tar.gz` URL is paired with a fixed SHA (breaks on every upstream release).
- `build_runtime.sh` uses a fixed `/tmp/lynis.tar.gz` (TOCTOU).

### Data
- Config save is non-atomic, and `_toml_str` escapes only `\n\r\t`, so a value containing `\x1b` corrupts the config permanently.
- Quarantine copies ignore short writes.
- Restore follows symlinked parent directories.
- `patch_finding` updates can be lost.
- `ui.terminal_show_raw` can't be saved ("Unknown config key").
- The Flatpak autostart `Exec` line is mis-quoted.
- `$` is not escaped in ExecStart.
- Redaction gaps: lists, `api_key`, `/root`, `/media`.

### CLI/GUI
- Confirm gates are inconsistent: `schedule set --disabled --apply`, `maldet monitor stop`, `scan --quarantine`, and the clamonacc watch-path Remove button.
- The wizard copy-hint command omits `--skip-harden --no-enable-firewall`.
- Possible races in quarantine restore and terminal polling.
- Exit-code semantics collide (1 = threats found, but also used for errors).

### Packaging
- Invalid OARS IDs in the metainfo.
- `sync_version.py` skips the spec, debian changelog, `.SRCINFO` and Flathub files, and can write `sha256sums=('SKIP')`.
- The Flathub manifest's pydantic-core pin conflicts with pydantic.
- The Debian scaffold is broken (compat duplication, native format with a revision, wrong install rename).
- Broken `../` links in `docs/packaging/distro-submit.md`.
- The helper shebang should be `/usr/bin/python3 -I`.
- No `uv` ecosystem in Dependabot.

### Checked and sound
- Actions are SHA-pinned, there is no `pull_request_target`, and PyPI uses Trusted Publishing.
- RPC: SO_PEERCRED + token with `compare_digest`, 0700 data dir, 0600 socket/token, exports confined to `exports/`.
- All tar extractions use `filter="data"`. Downloads are HTTPS and hash-checked before extraction.
- News XML is parsed with `defusedxml`. No TLS verification is disabled.
- The helper sets `PATH`/`HOME` itself and calls subprocesses with argv lists (no shell).
- The VirusEvent wrapper can't be shell-injected.
- The systemd timer fields are validated.
- No subprocess calls in `oysterav/`.
- Versions are consistent at 0.2.2.

---

## 5. Suggested fix order
1. **P1** (fail2ban injection), **P2/P3** (root-pinned digests), **P4** (dev helper + grant).
2. **S1–S3** (false "clean" results and wrong-file quarantine), plus the scan-report directory permissions.
3. **S4** (quarantine TOCTOU), the job-lock race, and the CI `inputs.version` injection plus least-privilege permissions.
4. The gate fixes **G1–G4**, so CI actually enforces what it claims.
5. Everything else.

---

## 6. Fix status (branch `fix/high-severity-audit`, uncommitted)

| ID | Status | Change |
|---|---|---|
| P1 | ✅ fixed | `validate_ip`/`validate_cidr` accept only IP-literal characters and reject IPv6 scope IDs. The fail2ban persist writer refuses `DEFAULT` and control/INI characters. Regression tests added. |
| P2 | ✅ fixed | `run-sealed` retired. The helper always refuses it, and `run_privileged_scanner` never sends runtime copies to pkexec. Privileged scans need root-owned system binaries. Pinning wasn't possible because chkrootkit/unhide are compiled locally. |
| P3 | ✅ fixed | The maldet digest is pinned in `oyst_core/privileged/pins.py`. The helper refuses any caller digest that doesn't match. |
| P4 | ✅ fixed | New `helper_site_trust.py` checks the site root, every ancestor and the `oyst_core` tree. The passwordless grant is refused for untrusted (dev) helpers. Expired or undated grants are revoked on reinstall instead of renewed. The expire timer never copies an untrusted `sys.path` insert. |
| S1 | ✅ fixed | Every requested privileged pack without a report becomes a `PackError`. Any scan with pack errors has `clean=False`. |
| S2 | ✅ fixed | clamscan exit code ≥2 raises `PartialScanError`, which keeps the findings and records the error. Subprocess output is decoded with `backslashreplace`. |
| S3 | ✅ fixed | Detections must end in ` FOUND`. The path is split on the last `": "`. Lines broken by newlines in filenames are re-joined. The summary section is ignored. |
| S4 | ✅ fixed | Open the parent directory by walking each component with `O_NOFOLLOW`. Open, `stat` and unlink go through `dir_fd`, with a dev/ino check before unlink. Vault names are now UUIDs (fixes long filenames). Short writes are looped. The DB row is removed if the unlink fails. |
| C1 | ✅ mitigated | The metainfo now states plainly that the Flatpak is not sandboxed. The redundant `--filesystem=home` was dropped. The host-RPC-client redesign has not been done. |
| C2 | ⏸ not attempted | Needs a real deb/rpm build and install test in distro containers. |

Gates after the fixes: ruff, ruff format, mypy, LOC, bandit and the security marker suite pass, with 1172 tests passing. The only failure is the pre-existing flaky G1 test, which also fails on the original code and sometimes makes the security-coverage gate fail.

## 7. Medium fix status (same branch, uncommitted)

| Area | Finding | Status |
|---|---|---|
| Privilege | Expired grants come back | ✅ The migration revokes expired or undated stamps. The expiry timer now uses absolute `OnCalendar=` + `Persistent=true`. |
| Privilege | Site-root trust checks only one dir | ✅ (with P4) Every ancestor and the package tree are checked. |
| Privilege | Scan-report dir 0750 + chown follows symlinks | ✅ Directories are walked with `O_NOFOLLOW` and must be root-owned (dirs 0711/0755). Reports get `fchown`/`fchmod` on the fd. |
| Privilege | `pacman -Sy` partial upgrades | ✅ Builders use `-S --needed --noconfirm`. The root validator now refuses `-Sy`. |
| Supply chain | AUR upgrades with `--noconfirm` | ✅ Skipped by default. Opt in with `updates apply --confirm-aur` (CLI) or RPC `confirm_aur: true`. |
| Supply chain | fangfrisch installed without hash pins | ✅ Hashed requirements file shipped; install uses `--require-hashes --no-deps --only-binary :all:`. |
| Supply chain | Fedora `dnf` arch suffix | ✅ Suffix stripped. |
| Supply chain | One bad feed aborts news | ✅ `ParseError` caught per source. |
| RPC/jobs | Job lock race | ✅ Conditional `UPDATE … WHERE job_id IS NULL` with a rowcount check. |
| RPC/jobs | Cancel/release corruption, 2 h stale | ✅ Owner-checked release. A double cancel no longer frees a live lock. Staleness is now heartbeat-based (10 min, 60 s beat). |
| RPC/jobs | Server robustness | ✅ Per-frame deadline, `accept()` errors survived, working `stop()`, refuses a live socket, catches `RecursionError`, backlog 32, JSON `busy` reply. |
| Scan/data | Unanchored exclude regexes | ✅ Absolute paths only; emits `^escaped(/\|$)`. |
| Scan/data | Basename-keyed quarantine guards | ✅ Only real install/runtime locations are protected. |
| Scan/data | Long filenames / phantom rows | ✅ (with S4) |
| Scan/data | VirusEvent `strip()` | ✅ Exact env value used. |
| GUI/CLI | Pango markup injection | ✅ All 81 rows/banners go through `plain_rows.py` (`use_markup=False`). A test forbids raw constructors. |
| GUI/CLI | Firewall delete hits a broader rule | ✅ The `From` column is parsed and v6 pairs are merged. Only exactly expressible rules can be removed. CLI gains `--from`/`--direction`. |
| GUI/CLI | Wizard reset wipes setup state | ✅ No pre-reset; Cancel preserves state. |
| GUI/CLI | CLI quarantine tracebacks | ✅ Structured error, `ExitCode.ERROR`. |
| GUI/CLI | Blocking main-loop calls | ✅ Scan poll, wizard and finding list moved off the main loop. A few quick `config_get` calls remain synchronous. |
| GUI/CLI | GUI is the backend | ⚠️ Partly mitigated: quitting asks for confirmation during an active job, and a backend start failure shows an error. The architectural fix (separate `oyst-cli serve`, no in-process fallback) is **not done**. |
| CI | `inputs.version` injection | ✅ Passed via `env:` and semver-validated; no `${{ }}` left in `run:`. |
| CI | Workflow-wide write token | ✅ `contents: read` by default, write only per job, `persist-credentials: false`, `environment: release`. |
| CI | Force republish from any branch | ✅ Restricted to `refs/heads/main`. |
| CI | Unpinned tools / no checksums | ✅ fpm 1.17.0, semgrep tag+digest, bandit/pip-audit pinned, `SHA256SUMS` uploaded. Attestations not added. |
| CI | PyPI auto-publish never fires | ✅ `release.yml` dispatches `publish-pypi.yml` (`workflow_dispatch` is exempt from the GITHUB_TOKEN rule). |
| Gates | G1 flaky DoS test | ✅ Deterministic (20/20 runs). |
| Gates | G2 bandit skipping files | ✅ Python 3.12 + fails on skipped files. |
| Gates | G3 pip-audit on the wrong venv | ✅ Audits the exported `uv.lock` with hashes. |
| Gates | G4 GUI tests without `gi` | ✅ Lazy `gui/__init__`, `importorskip`. |

**Manual repo settings needed:** create a protected `release` environment (required reviewers, `main` only). The PyPI trusted publisher stays on `publish-pypi.yml` / environment `pypi`.

**Gates:** `scripts/check.sh --format` passes end to end: 1240 tests, security coverage 87%, bandit with 0 files skipped, pip-audit on the lockfile clean. The suite also passed 5 more times in a row.

## 8. Low fix status (same branch, uncommitted)

All Low items in section 4 are fixed except where noted.

- **Privilege**
  - Rich-rule lockout guard compares ports numerically (`022`, tabs).
  - `ensure-fdpass` accepts only `clamav-clamonacc`.
  - fail2ban persist merges and re-validates IPs.
  - `--include-list` files must be root-owned under `/etc/clamav` or owned by the polkit caller.
  - The OnAccess deny-list covers `/bin`, `/sbin`, `/lib*`, `/snap` and `/nix`, and is also checked on the resolved path.
  - maldet monitor paths are charset-restricted, must exist and can't be system dirs.
  - `write_text_nofollow` is atomic (temp file + `os.replace`, nofollow walk, keeps owner) and FIFO-safe.
  - Reprobe units fixed.
  - Helper and expire-script shebangs use `-I`. This also fixed a bug: the expire script had an indented shebang and would never run.
  - Delete labels show `from`.
- **RPC**
  - Token compared as bytes; token creation is atomic (`link`/`replace`, nofollow).
  - Typed param helpers return `validation_error`/`not_found`.
  - `fail2ban.jail` is validated.
  - List limits are clamped to 1..10000.
  - `config.set` values are redacted in logs and large params truncated.
  - (`RecursionError` and live-socket refusal were done earlier.)
- **Network**
  - Size-capped streaming downloads.
  - HTTPS-only redirects (`oyst_core/net_util.py`).
  - Release `html_url` must point at this repo.
  - Feed links limited to http(s); control characters stripped.
  - maldet uses the versioned `maldetect-1.6.6.tar.gz` (hash verified equal to the pin).
  - `build_runtime.sh` uses `mktemp -d`.
- **Data**
  - Atomic config save with full TOML control-char escaping. A corrupt config is backed up and defaults are used.
  - Quarantine restore: nofollow parent walk, no `mkdir -p`, O_EXCL create, partial cleanup.
  - `patch_finding` runs in one transaction; bulk handling tolerates per-item errors.
  - A reused `job_id` can't overwrite another scan.
  - Exports are created O_EXCL 0600.
  - `ui.terminal_show_raw` can be saved.
  - Flatpak autostart `Exec` fixed.
  - systemd `$`/`%` escaping.
  - Redaction covers lists and more key names, `/root` and `/media`; EventLog messages are redacted; rotated logs are 0600.
- **CLI/GUI**
  - Consistent `--confirm` gates (exit 4).
  - Confirm dialog for removing clamonacc watch paths.
  - Safe copy hints.
  - Restore and terminal-poll races fixed.
  - News URIs limited to https; CLI strips control characters.
  - Errors exit `ExitCode.ERROR` (2), never 1; the real exit code is logged.
- **Packaging**
  - Valid OARS (appstreamcli passes).
  - `sync_version.py` covers spec, debian changelog, `.SRCINFO` and Flathub. SKIP sha256 fails when the tag exists or with `--strict-sha256`, so it doesn't block pre-tag release CI.
  - Flathub pydantic-core matches `uv.lock`.
  - Debian scaffold fixed (no `compat`, `3.0 (quilt)`, helper installed at the right path).
  - `python3 -I` helper shebangs everywhere.
  - fpm `after-remove.sh` is wired in.
  - `distro-submit.md` links fixed.
  - SECURITY.md points to GitHub private vulnerability reporting.
- **Pre-existing bug found:** circular import (`schedule_linger` ↔ `privileged.auth_grant`) when `schedule_linger` is imported first. Fixed with a lazy import.

**Behavior changes:**
- Errors exit 2 instead of 1.
- `scan --quarantine`, `schedule set --disabled --apply`, `maldet monitor stop` and `terminal clear` now need `--confirm`.
- Boolean RPC params reject unrecognised strings.
- A corrupt config file is moved aside instead of crashing.

**Gates:** `scripts/check.sh --format` passes: 1411 tests, security coverage 87%, bandit with 0 files skipped, pip-audit clean. The suite passed 3 more consecutive runs, and with `gi` blocked it gives 1367 passed / 12 skipped with no collection errors.

**Still open:**
- The GUI runs the backend in-process (architectural).
- The fpm deb/rpm packages haven't been install-tested in distro containers (C2).
- No build attestations.
- A few synchronous `config_get` calls remain in the wizard.

## 9. Remaining open items — fixed (same branch, uncommitted)

- **GUI no longer hosts the backend.**
  - `ensure_rpc_server` now spawns `oyst-cli serve --idle-exit 900` as a separate, detached process (`oyst_core/serve_spawn.py`: own session, `python -I`, pinned `oyst_core`, 0600 `serve.log`) instead of a thread in the GTK process.
  - The GUI uses `OystClient(local_fallback=False, autostart=True)`, so it never dispatches in-process. The CLI keeps the same-UID fallback.
  - Progress-enabled installs/runtime calls now go through RPC with a `progress_token` and `progress.get` polling (`oyst_core/rpc_progress.py`), so they get token/peercred auth and server-side audit like every other call.
  - Jobs survive quitting the GUI; the quit dialog now says so.
  - `serve --idle-exit` stops only when there are no connections and no active job.
  - **Verified end-to-end with the real GUI (isolated HOME):**
    - the backend ran as its own process/session;
    - the socket was 0600;
    - the backend kept running after the GUI exited.
- **C2: deb/rpm packaging rebuilt and install-tested.**
  - Packages are now arch-independent (`_all.deb`, `.noarch.rpm`).
  - The wheel is unpacked without bundled deps into the root-owned private prefix `/usr/lib/oysterav/python`.
  - Entry points and the helper are `#!/usr/bin/python3 -I` launchers.
  - Depends: `python3 (>= 3.12)` and `python3-pydantic (>= 2)`.
  - The dead `policykit-1` dependency became `pkexec|policykit-1, polkitd|policykit-1`; it made the .deb uninstallable on Debian 13.
  - New `scripts/smoke_native_packages.sh` checks, in clean Debian 13, Ubuntu 26.04 and Fedora containers:
    - install;
    - files, ownership and permissions;
    - no bundled deps;
    - CLI, GUI import, helper usage, helper site-trust.
  - All three pass locally (podman). The release workflow runs it before upload.
  - Ubuntu 24.04 is unsupported: it ships pydantic 1.x, and the package correctly refuses to install there.
- **Build provenance.** The release job attests every staged asset with `actions/attest-build-provenance@4d101475…` (v4.2.2), adding `id-token: write` and `attestations: write` to that job only. `docs/packaging/release.md` documents `gh attestation verify`.
- **Wizard main-loop calls.** Runtime mode, auto-quarantine and the saved firewall backend now load in worker threads. Auto-Install no longer re-reads preferences over the user's toggles.

**Gates:** `scripts/check.sh --format` passes (1426 tests, security coverage 87%, bandit 0 skipped, pip-audit clean).

**Nothing from the audit remains open in code.** Two things can only be proven by a real tagged release run on GitHub: the attestation step, and the container smoke step running under Docker on the runner. Both were validated locally only (actionlint, plus the same smoke script under podman).
