# Hardening audit — July 2026

Structured full-stack security review of oysterAV (privileged helper, RPC, ClamAV
host co-control, CI/repo posture). Threat model: local same-UID malware or
malicious content under `/home` on a single-user wheel desktop. Out of scope:
remote attackers without a local foothold; formal verification / fuzzing campaigns.

## Research inputs

| Source | Relevance |
|--------|-----------|
| [polkit apps guide](https://www.freedesktop.org/software/polkit/docs/latest/polkit-apps.html) | Prefer `auth_admin`; KEEP only when args do not change auth meaning |
| [polkit(8) KEEP](https://man.archlinux.org/man/polkit.8) | Passwordless YES rules for fixed action IDs are OK if scope stays narrow |
| [CVE-2021-4034 / PwnKit](https://nvd.nist.gov/vuln/detail/cve-2021-4034) | Scrub env into pkexec; never trust caller environment as root |
| [OpenSSF Scorecard / SCM practices](https://best.openssf.org/SCM-BestPractices/github) | SECURITY.md, pinned Actions, read-only tokens, Dependabot, Scorecard CI |
| [ClamAV#544](https://github.com/Cisco-Talos/clamav/issues/544), [#1024](https://github.com/Cisco-Talos/clamav/issues/1024) | Prevention + VirusEvent quirks; on-access DoS on busy trees |

## Method

1. Matrix every polkit `argv1` builder → validator → allowlisted binary.
2. Review auth-grant scope and KEEP / YES semantics.
3. Review RPC token/socket modes, peercred, in-process fallback trust.
4. Map ADR-008 defaults to ClamAV community pitfalls.
5. Repo hygiene vs OpenSSF checklist (cheap fixes in this pass).

## Severity table

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| H-01 | P1 | `clamonacc` `--include-list=` / `--exclude-list=` used `Path.is_file()` (follows symlinks); root helper could open attacker-chosen targets via TOCTOU/symlink | **Fixed** — `O_NOFOLLOW` + regular file + reject world-writable (`helper_validate.py`) |
| H-02 | P1 | `lynis --profile` accepted absolute `/usr`/`/etc` paths without fd checks | **Fixed** — `O_NOFOLLOW`, regular file, root-owned |
| H-03 | P1 | No `SECURITY.md` / Scorecard / Dependabot; CI Actions on mutable tags; no top-level `permissions: contents: read` | **Fixed** — this pass |
| H-04 | P1 | XDG data dir created without forcing `0700` (token/socket rely on file modes alone) | **Fixed** — `data_dir()` chmod `0700` |
| H-05 | P2 | Non-pkexec `run_command` inherits full process env (session secrets visible to child scanners) | **Accepted residual** — document; pkexec paths scrubbed |
| H-06 | P2 | Audit redaction covers `/home/…` only; other user paths may remain in logs | Deferred |
| H-07 | Info | Auth grant YES for `systemctl-up` + `maldet-config` only (active/local, 7d TTL); stop/disable stay passworded | OK — do not expand scope |
| H-08 | Info | RPC: token `0600`, peercred UID match, `compare_digest`; in-process fallback = same-UID CLI trust | OK |
| H-09 | Info | ClamAV: path-scoped includes, prevention opt-in, owned VirusEvent, no MountPath auto | Docs/GUI copy refreshed |
| H-10 | P0 | None found this pass (no confirmed priv-esc / auth bypass / root exec from user-writable embed path when site_root rules hold) | — |
| A-01 | P1 | `run-sealed` executed sealed binary with unvalidated argv | **Fixed** — `_validate_scanner_argv` in `helper_sealed_scanner` / `scanner_exec` |
| A-02 | P1 | `install-script` sealed only `install.sh`; siblings mutable before pkexec | **Fixed** — helper re-verifies tarball SHA and extracts under root seal |
| A-06–A-07 | P2 | Concert disclosure argv mismatch; scan-concert silent unknown `--pack=` | Tracked in remediation (Phase 2) |

## Privileged helper matrix (summary)

| argv1 / action | Validation highlights | Notes |
|----------------|----------------------|-------|
| `systemctl` | Unit allowlist | Stop/disable (always passworded) |
| `systemctl-up` | AV units + start/enable/restart | Lifecycle grant passwordless optional |
| `maldet-config` | Fixed verb shapes | In grant set |
| `firewall` / ufw / firewalld | Rule builders | Concert / harden paths |
| `clamd-cocontrol` | Conf path regex under `/etc/clamav` | Surgical keys only (ADR-008) |
| `clamonacc` (scanner run) | Flags + list paths | H-01 remediation |
| `setup-harden` / `setup-concert` / `scan-concert` | Sealed tarball SHA; pack allowlists; policy v11 | Concert recipes (ADR-009) |
| `install-script` | Tarball SHA-256 + extract under seal | Do not accept install.sh-only |
| `rkhunter-whitelist` / scanners / `run-sealed` | Flag allowlists; lynis profile; sealed argv | A-01 remediation |
| Helper install / site_root | Root-owned site_root (tests may relax) | Confirm after policy bumps |

Empty argv and env injection into helper: scrubbed pkexec env + helper `_secure_exec_env` remain required defenses (PwnKit class).

## Auth grant + KEEP

- Grant emits **YES** for `SERVICE_LIFECYCLE_ACTION_IDS` only (`systemctl-up`, `maldet-config`).
- Grant installation **fails closed** if the expire timer cannot be installed (no durable YES without TTL).
- Product decision: do **not** expand passwordless scope this pass.
- `auth_admin_keep` on interactive admin actions is UX; grant path does not use KEEP with variable-dependent decisions.

## RPC / env

- Token atomic create + `0600`; socket expected under data dir; peercred rejects cross-UID.
- In-process `OystClient` fallback inherits CLI trust (same UID) — not a network surface.
- Residual H-05: catalog future scrub for long-lived scanner children if needed.

## ClamAV co-control vs community

Defaults remain detect-friendly; prevention after path selection. Operator guide now
calls out prevention DoS and VirusEvent latency. Real-time GUI co-control group
describes opt-in / path-scoped / performance cost.

## Repo / supply-chain

Added: root `SECURITY.md`, `.github/workflows/scorecard.yml` (pinned SHAs,
`continue-on-error: true`, `publish_results`), Dependabot (Actions + pip), CI
`permissions: contents: read` + pinned `checkout` / `setup-uv`.

Treat Scorecard badge as **informational** until sustained score ≥ 7 and gating
is an explicit product decision.

## Residual risk

- Local attacker with wheel can always use polkit as admin; oysterAV cannot
  outrank that.
- Host ClamAV/kernel fanotify limitations and AUR helper prompts remain outside
  oysterAV’s policy.
- Formal pen-test / fuzzing of helper argv parsers is a follow-up if Scorecard
  or production incidents warrant.

## Operator note

After pulling helper/policy changes:

```bash
oyst-cli install-privileged-helper
./scripts/check.sh --quick
```

## Citations

- FreeDesktop polkit application authors guide (auth_admin / KEEP).
- NVD CVE-2021-4034.
- OpenSSF Scorecard and GitHub SCM best practices.
- Cisco-Talos ClamAV issues #544 and #1024.
- In-tree: ADR-008, `docs/user-guide/clamonacc-prevention.md`, `packaging/polkit/`.
