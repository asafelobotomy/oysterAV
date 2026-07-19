# ADR-006: Dependency scope (integrate vs skip)

## Status

Accepted

## Context

oysterAV orchestrates mature Linux security tools (ADR-001) and vendors upstream
artifacts in full mode (ADR-004). After reviewing half-wired, optional, and
commonly requested tools, we need an explicit integrate / defer / skip policy so
the product stays focused on a desktop-friendly orchestrator with a ClamAV spine.

## Decision

### Required spine (do not replace)

- **clamav** + **freshclam** remain required for malware path scanning and CVD updates.

### Integrate / deepen

- **clamonacc** — finish full-mode runtime wiring (same ClamAV product family).
- **fangfrisch** — optional pack that adds unofficial ClamAV DBs **after** freshclam.
- **maldet** — optional; layer with ClamAV (`scan_clamscan`); oysterAV vault is primary quarantine.
- **rkhunter** + **chkrootkit** — keep both recommended (complementary heuristics).
- **lynis** — recommended audit; suite profile runs audit stage after path scans.
- **firewall** / **fail2ban** — host-integrated; complementary jobs.

### Do not add

| Tool | Reason |
|------|--------|
| **Standalone YARA pack** | ClamAV already loads `.yar`/`.yara`; maldet has native YARA; see `docs/cli/clamav-yara.md`. |
| **Wazuh / OSSEC** | Always-on HIDS agents — ops surface beyond desktop orchestrator scope. |
| **Falco** | eBPF runtime security — different product class. |

### Defer

| Tool | Reason |
|------|--------|
| **AIDE** | Better true FIM than rkhunter `propupd`, but baseline UX is heavy for desktop; may become optional later without replacing rkhunter. |

### Soft dependencies (not packs)

- **inotify-tools** — required for maldet monitor; surfaced in doctor.
- **docker** — optional for lynis container audit only.

## Consequences

- Detection quality improves via fangfrisch without a second malware scanner UX.
- Scope docs prevent “everything HIDS” creep while leaving AIDE as a future optional FIM.
- Suite profile semantics must treat lynis as audit, not path scan.
