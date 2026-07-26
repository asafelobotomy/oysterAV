# Full-surface audit — 2026-07-26

Findings-only review across CLI, RPC, GUI, privileged helper, host co-control,
Privilege Concert, quarantine/VirusEvent, CI/supply-chain. Remediation is
tracked in severity-ordered waves (see Status column as waves land).

**Threat model:** local same-UID malware or malicious content under `$HOME` on a
single-user wheel desktop. Out of scope: remote attackers without a foothold;
formal fuzzing / pen-test campaigns.

**Prior art:** [hardening-audit-2026-07.md](hardening-audit-2026-07.md),
[full-surface-audit-2026-07-23.md](full-surface-audit-2026-07-23.md),
[asvs-checklist.md](asvs-checklist.md).

## Executive verdict

No P0 privilege-escalation or cross-UID RPC auth bypass while helper
`site_root` root-owned rules hold. July Waves 1–3 controls still hold. This
pass opens High residuals (install-script TOCTOU; quarantine refuse-guard skip
paths) plus Medium privilege/DoS/CI gaps.

## Severity table

| ID | Sev | Surface | Finding | Status |
|----|-----|---------|---------|--------|
| A-02-R | High | Helper install | SHA on `O_NOFOLLOW` fd then path reopen for extract (TOCTOU) | **Fixed** (Wave 1) |
| F-01 | High | Quarantine | `quarantine_refuse_reason` skipped on VirusEvent / history / RPC add | **Fixed** (Wave 1) |
| F-02 | Med | VirusEvent | User XDG wrapper; helper accepts any absolute `oyst-virusevent` path | **Fixed** (Wave 2) |
| F-04 | Med | clamonacc | Process-mode `add_path` ignores `DENIED_INCLUDE_PREFIXES` | **Fixed** (Wave 2) |
| C-PKG-01 | Med | Concert / PM | Package args format-only after one `auth_admin` | **Fixed** (Wave 2) |
| H-AUTH-01/02 | Med | Auth grant | TTL timer/stamp not fail-closed in helper on passwordless paths | **Fixed** (Wave 2) |
| RPC-01/02 | Med | RPC DoS | Auth after 16 MiB parse; 8×120s idle accept slots | **Fixed** (Wave 3 — 15s idle) |
| F-05 | Med | CI | GUI `rg` gate matches pack-name labels | **Fixed** (Wave 4) |
| F-06 | Med | Supply-chain | Release / attacker-sim Actions on mutable tags | **Fixed** (Wave 4) |
| H-ENV-01 | Low | Helper | `fail2ban-client` without `_secure_exec_env` | **Fixed** (Wave 4) |
| RPC-03/04/05/07 | Low | RPC hygiene | Error leakage; non-object roots; LONG gaps; weak token | **Fixed** (Wave 3) |
| F-03 | Med | Quarantine | Delete is plain `unlink` (ASVS V8.3) | **Fixed** (Wave 5 — opt-in `secure_wipe`) |
| F-07/08/09 | Low | UX/parity | Ensure/auth GUI confirm; quarantine RPC dry-run | **Fixed** (Wave 5) |
| ASVS V7.4 | Gap | Audit | No tamper-evident / SIEM chain | Deferred |

## Still holding

H-01/H-02 symlink/`O_NOFOLLOW` list/profile checks; A-01 sealed scanner argv;
peercred + token + `0700`/`0600`; site_root refuse; concert `disclosure_only` /
pack fail-closed; env scrub on pkexec/`run_command`; passwordless YES scope
(`systemctl-up` + `maldet-config` only); ADR-002 GUI no security subprocess
(pytest); surgical ClamAV co-control (ADR-008).

## Operator note

After helper/policy waves (1–2, 4 helper env):

```bash
oyst-cli install-privileged-helper
./scripts/check.sh --quick
```
