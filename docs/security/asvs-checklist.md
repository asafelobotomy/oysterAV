# ASVS 5.0 coverage map (oysterAV)

This is a **coverage map** of OWASP ASVS 5.0 requirements against oysterAV
controls. It is **not** an ASVS Level 1 or Level 2 certification claim.

**Threat model (in scope):** local same-UID / wheel desktop; malicious content
or compromised GUI/CLI client under the user home; Unix JSON-RPC control plane;
polkit `oyst-helper`; audit logs; dependency/supply-chain hygiene.

**Out of scope:** remote attackers without a local foothold; stock web DAST/ZAP
against GTK; multi-tenant SaaS session models.

Status: `covered` | `partial` | `gap` | `n/a`

Living gates: [`test-gates.md`](test-gates.md). Adversarial suites:
`tests/test_security/`.

---

## Status legend

| Status | Meaning |
|--------|---------|
| covered | Automated gate or `@pytest.mark.security` test proves the control |
| partial | Some evidence; incomplete vs requirement intent |
| gap | In-scope; no adequate automated evidence yet |
| n/a | Outside product threat model (chapter or requirement) |

---

## V1 — Encoding and sanitization / injection

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V1.1.1 | Input validation for untrusted data | L1 | covered | `test_validators_adversarial`, `test_helper_argv_injection`, `test_rpc_adversarial` | Reject-not-sanitize for helper argv |
| V1.2.1 | Output encoding for logs | L1 | partial | `test_audit_redaction`, `redact_paths` | Path redaction; not full contextual encoding |
| V1.5.x | Injection resistance (OS command) | L1/L2 | covered | Allowlisted argv builders; Bandit; security argv corpora | No shell strings for privileged ops |
| V1.5.x | Injection (SQL) | L1 | n/a | — | SQLite audit uses parameterized SQL |
| V1.5.x | Injection (LDAP/XPath/etc.) | L1 | n/a | — | Not used |

## V2 — Authentication

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V2.1.1 | Authn of control plane | L1 | covered | `rpc_auth` token + `test_rpc_auth_hardening` / `test_rpc_adversarial` | Unix socket + token |
| V2.2.x | Password / credential storage | L1 | covered | Token file mode 0600; `secrets.token_urlsafe` | Not user passwords |
| V2.5.x | Credential recovery flows | L1 | n/a | — | No account recovery |
| V2.7.x | MFA | L2 | n/a | — | Desktop polkit prompts, not MFA |
| V2.x | Peer identity | L1 | covered | `verify_peer_credentials` (SO_PEERCRED) | Checked once per accept |
| V2.x | Same-process local fallback | L1 | partial | Documented in ADR-002 / client | `_local_fallback` skips token (same UID) |

## V3 — Session management

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V3.* | HTTP session cookies / idle timeout UX | L1/L2 | n/a | — | No browser sessions; one RPC request per connection |

## V4 — Access control

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V4.1.1 | Principle of least privilege | L1 | covered | ADR-009 concert; polkit allowlists; passwordless narrow scope | |
| V4.2.x | Function-level access control | L1 | covered | RPC method registry; helper subcommand allowlist | |
| V4.3.x | Multi-tenant horizontal authz | L2 | n/a | — | Single-user desktop |
| V4.x | Cross-UID RPC | L1 | covered | Peercred UID mismatch → `auth_failed` | |

## V5 — Validation / business logic

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V5.1.1 | Structured input validation | L1 | covered | Validators + RPC `params` dict guard (`serve.handle`) | |
| V5.2.x | Confirm gates for destructive ops | L1 | partial | `test_confirm_safety` | CLI `--confirm`; expand as mutators land |
| V5.3.x | Anti-automation / CAPTCHA | L2 | n/a | — | Local desktop |
| V5.x | Firewall SSH lockout heuristics | L1 | covered | `test_firewall_security_props`, lifecycle soft-stop / fail-closed | |

## V6 — Cryptography

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V6.2.x | Random for secrets | L1 | covered | `secrets` module for RPC token | |
| V6.3.x | TLS for all remote APIs | L1 | partial | HTTPS scheme gate on downloads / news | Unix RPC is local AF_UNIX, not TLS |
| V6.4.x | Key management HSM | L2 | n/a | — | |
| V6.x | Integrity of sealed scanners / install | L1 | covered | SHA-256 verify; `test_helper_seal_install_adversarial` | |

## V7 — Error handling and logging

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V7.1.1 | No sensitive data in errors | L1 | covered | RPC scrubbed `internal_error` + malformed-frame message; audit path redaction | |
| V7.2.x | Security event logging | L1 | covered | `SecurityAudit`; firewall.mutate hashes | |
| V7.4.x | Log integrity / SIEM | L2 | gap | Local SQLite audit DB | No tamper-evident chain / remote SIEM |

## V8 — Data protection

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V8.1.x | Sensitive data at rest | L1 | covered | `data_dir` 0700; token/socket 0600 | |
| V8.2.x | Sensitive data in transit | L1 | partial | AF_UNIX local only | |
| V8.3.x | Secure deletion | L2 | partial | Optional `quarantine.secure_wipe` overwrite before unlink | SSD reclaim limits documented; default off |

## V9 — Communication

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V9.1.x | TLS / cert pinning for HTTP clients | L1 | partial | HTTPS-only fetches | System trust store; no pinning |
| V9.2.x | Backend HTTP APIs | L1 | n/a | — | No public HTTP API |

## V10 — Malicious software / unwanted code

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V10.2.x | Integrity of deployed components | L1 | partial | Runtime checksums; sealed helper | Distro packaging varies |
| V10.3.x | Subresource integrity (web) | L1 | n/a | — | |
| V10.x | Detection-path smoke (EICAR) | L1 | covered | `test_eicar_detection_path` (mocked; `OYST_EICAR_LIVE=1` opt-in) | |

## V11 — Business logic (orchestrator)

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V11.1.x | Workflow abuse / skip steps | L1 | covered | `test_concert_abuse` + `CONCERT_ABUSE_CASES` | Soft-fail mid-step after argv accept remains by design |
| V11.x | Privilege concert single-auth | L1 | covered | ADR-009; helper concert recipes | |

## V12 — Files and resources

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V12.1.x | Path traversal | L1 | covered | Validators; sealed/install path checks; monitor mode | |
| V12.3.x | Unrestricted file upload (web) | L1 | n/a | — | |
| V12.4.x | Temporary file safety | L1 | partial | `/tmp`/`/var/tmp` constraints + O_NOFOLLOW | |

## V13 — API / RPC

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V13.1.1 | API authentication | L1 | covered | Token + peercred | |
| V13.2.x | Mass assignment / unexpected params | L1 | covered | `Case`/`Expect` RPC corpora in `test_rpc_adversarial` | Not every handler exhaustively fuzzed |
| V13.3.x | Rate limiting / DoS bounds | L2 | covered | 16 MiB frame cap; accept semaphore(8); one-shot conn (`test_rpc_dos_bounds`) | No per-method rate limit |
| V13.4.x | GraphQL | L1 | n/a | — | JSON-RPC only |

## V14 — Configuration

| ASVS ID | Title | L1/L2 | Status | Evidence | Gap notes |
|---------|-------|-------|--------|----------|-----------|
| V14.1.x | Secure defaults | L1 | partial | Token auto-create 0600; managed firewall prefs | |
| V14.2.x | Dependency / component hygiene | L1 | covered | pip-audit; Gitleaks; Scorecard; Semgrep | |
| V14.3.x | Secrets in repo | L1 | covered | Gitleaks CI | |
| V14.5.x | Debug endpoints in prod | L1 | partial | Terminal log / doctor | No remote debug port |

## Chapter-level n/a (web / cloud)

| Chapter | Status | Rationale |
|---------|--------|-----------|
| Classic browser session / CSRF / CSP | n/a | GTK client + AF_UNIX RPC |
| OAuth / OIDC / SAML | n/a | No federated IdP |
| Multi-tenant / cloud tenancy | n/a | Single-user desktop |
| Mobile app store / IPC (iOS/Android) | n/a | Linux desktop only |

---

## Priority gaps (for a separate remediation plan)

1. **V7.4** — audit log integrity / export for operators (deferred)
2. **Local fallback auth** — document operator expectations; optional harden later

Optional operator exercise: [`attacker-sim.md`](attacker-sim.md) (non-PR-blocking).

Remediating remaining gaps requires a **separate approved plan** (findings-first policy).
