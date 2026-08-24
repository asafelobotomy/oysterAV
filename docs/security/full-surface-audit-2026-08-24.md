# Full-surface audit — 2026-08-24

Findings-only review across CLI, RPC, GUI, privileged helper, host co-control,
Privilege Concert, quarantine/VirusEvent, runtime modes, and contract/docs.
Remediation waves A–D landed the same day (see Status column).

**Threat model:** local same-UID malware or malicious content under `$HOME` on a
single-user wheel desktop. Out of scope: remote attackers without a foothold;
formal fuzzing / pen-test campaigns.

**Prior art:** [full-surface-audit-2026-07-26.md](full-surface-audit-2026-07-26.md),
[hardening-audit-2026-07.md](hardening-audit-2026-07.md),
[asvs-checklist.md](asvs-checklist.md).

## Executive verdict

No cross-UID RPC auth bypass while helper `site_root` root-owned rules hold.
July Waves 1–5 controls still hold. August findings (Critical scan-report race,
firewalld SSH ordering, fdpass fail-closed, system VirusEvent wrapper, concert
gaps, ADR-008 hygiene, CLI/GUI confirms, contract drift) are **Fixed** in waves
A–D.

## Severity table

| ID | Sev | Surface | Finding | Status |
|----|-----|---------|---------|--------|
| P-01 | Critical | Helper / scan-concert | `/var/tmp` report race; symlink follow | **Fixed** (Wave A) |
| F-01 | High | Firewall / setup | firewalld enable before SSH | **Fixed** (Wave A) |
| F-02 | High | ClamAV / ADR-008 | Invalid vendor ExecStart → stripped fdpass | **Fixed** (Wave A) |
| P-02 | High | VirusEvent | Host VirusEvent → user-writable XDG wrapper | **Fixed** (Wave A) |
| P-03 | Med | Concert | Standalone `rkhunter.scan` double-prompt | **Fixed** (Wave B) |
| P-04 | Med | Config | `config.set` disable_tests elevates on autosave | **Fixed** (Wave B) |
| P-05 | Med | Elevate | `resolve_helper_path` execute-only | **Fixed** (Wave B) |
| F-04 | Med | clamonacc | Include deny-list omitted busy trees | **Fixed** (Wave B) |
| F-05 | Med | ADR-008 | Ensures force `0644` on host conf | **Fixed** (Wave B) |
| F-06 | Med | Concert | `clamonacc.enable` two elevations | **Fixed** (Wave B; unit path) |
| F-07 | Med | Runtime | Full private DB vs host on-access | **Fixed** (Wave B; doctor note) |
| F-08 | Med | ADR-008 | OnAccess append without neutralizing host keys | **Fixed** (Wave B) |
| G-06 | Med | GUI Shield | fail2ban toggle omits `boot=` | **Fixed** (Wave C) |
| G-07 | Med | GUI Shield | Jail enable no confirm | **Fixed** (Wave C) |
| C-08 | Med | CLI | `clamonacc enable/disable` lack `--confirm` | **Fixed** (Wave C) |
| C-09 | Med | CLI | `job clear` / `cancel --force` lack `--confirm` | **Fixed** (Wave C) |
| C-10 | Med | CLI | firewalld reload lack `--confirm` | **Fixed** (Wave C) |
| G-11 | Med | GUI Schedule | Schedule apply second linger prompt | **Fixed** (Wave C) |
| D-01 | Med | Contract | Wave-5 still documented as CLI-first | **Fixed** (Wave D) |
| P-06 | Low | Tests | argv1 asserts omit `update-concert` | **Fixed** (Wave D) |
| P-07 | Low | Auth grant | Helper reinstall refreshes grant TTL | **Fixed** (Wave B) |
| P-08 | Low | Lists | Include/exclude lists allow group-writable | **Fixed** (Wave D) |
| F-10 | Low | Quarantine | Vault payloads inherit umask | **Fixed** (Wave D) |
| F-11 | Low | Logging | EventLog stores full threat paths | **Fixed** (Wave D) |
| F-12 | Low | Prevention | Defaults ExcludeUname to `clamav` | **Fixed** (Wave D) |
| G-13 | Low | Wizard | Per-item Ensure bypasses concert | **Fixed** (Wave C; copy) |
| G-14 | Low | GUI | Inline import of `privileged.validators` | **Fixed** (Wave C) |
| I-01 | Info | Polkit | `auth_admin_keep` on systemctl-up / maldet-config | By design |
| I-02 | Info | RPC | In-process fallback skips token/peercred | Documented |

## Residual

- Process-mode `clamonacc.enable` (no distro unit) may still elevate twice when clamd is down; unit-path `enable-stack` is single-prompt.
- Reinstall helper after Wave A so system VirusEvent wrapper is on disk:
  `oyst-cli install-privileged-helper`

## Still holding

- argv1 ↔ polkit `POLICY_VERSION=12` ↔ helper dispatch (incl. `update-concert`)
- Passwordless grant scoped to `systemctl-up` + `maldet-config`; TTL fail-closed
- RPC peercred + token + `0600` socket/token; DoS idle bounds (July Wave 3)
- ADR-002: no `subprocess` / `pkexec` / `systemctl` under `oysterav/`
- GUI↔CLI↔RPC parity machinery exact match (method existence)
- Surgical ClamAV marked blocks (no wholesale rewrite)
- UFW SSH-safe allow-before-enable; quarantine `O_NOFOLLOW` / vault containment
- Install-script SHA + `O_NOFOLLOW` + extract `filter="data"`; sealed scanner argv
- Job scans / Update all / firewall batch use single-elevation concerts

## Operator note

```bash
oyst-cli install-privileged-helper
./scripts/check.sh --quick
```
