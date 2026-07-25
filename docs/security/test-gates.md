# Security verification gates (oysterAV)

Commit-time gates for privileged surfaces. Mapped loosely to **OWASP ASVS 5.0**
automatable controls (not a Level 2 certification claim).

## Gates

| Gate | Command / location | Control |
|------|--------------------|---------|
| Security marker suite | `uv run pytest -m security -q --no-cov` | Validation, helper argv, firewall props, RPC auth, audit redaction |
| Security module coverage ≥85% | `uv run python scripts/check_security_coverage.py` | Regressions in privileged modules cannot drop below floor |
| Bandit MEDIUM+ | `uv tool run bandit -c bandit.yaml -r oyst_core oyst_cli -ll -ii` | SAST (injection / unsafe subprocess patterns) |
| pip-audit | `uv tool run pip-audit` | Known dependency CVEs |
| Gitleaks | `.github/workflows/security-scan.yml` | Secrets in git history / working tree |
| Semgrep | `.github/workflows/security-scan.yml` (`p/python`, `p/security-audit`) | Additional SAST on `oyst_core` / `oyst_cli` |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` (blocking) | Supply-chain / repo hygiene score |
| GUI subprocess ban | CI `rg` + `test_no_security_subprocess_in_gui` | ADR-002: GUI uses `OystClient` only |
| Global coverage | `fail_under = 65` in `pyproject.toml` | Broader quality (not a security floor) |

`scripts/check.sh` (non-`--quick`) and GitHub CI run the security marker suite,
security coverage, Bandit, and pip-audit after the usual triad.

## ASVS-oriented mapping

| Theme | Evidence in tests |
|-------|-------------------|
| Input validation / injection | `test_validators_adversarial`, `test_helper_argv_injection` |
| Privilege / command construction | `test_helper_fw_lifecycle`, firewall security props |
| Local RPC authentication | `test_rpc_auth_hardening` (token + peercred UID) |
| Sensitive logging | `test_audit_redaction` |

## How to add a security test

1. Put it under `tests/test_security/`.
2. Mark with `@pytest.mark.security`.
3. Prefer property assertions (reject corpora, argv shape, auth fail-closed) over
   behavioral happy-paths already covered in `tests/test_core/`.
4. If you add a security-critical module, include it in
   `scripts/check_security_coverage.py` `SECURITY_MODULES`.

## Bandit skips

Documented in [`bandit.yaml`](../../bandit.yaml): `B404` / `B603` / `B607` for
allowlisted `subprocess` argv construction in the privileged helper. Inline
`# nosec B108` is used only for path-redaction regex literals that mention
`/tmp` (not temp-file I/O).

## Residuals

- Full ASVS Level 2 certification and live GUI DAST/ZAP remain out of scope
  (commit-time gates only; no Level 2 claim).
- Peercred cross-UID is covered in `test_rpc_auth_hardening` via mocked
  `SO_PEERCRED` (no live cross-UID socket required).
- Dependency CVE exceptions (if ever needed) go in
  [`dependency-exceptions.md`](dependency-exceptions.md) with an expiry note.
- Gitleaks/Semgrep run in GitHub Actions (`security-scan.yml`); they are not
  duplicated in `scripts/check.sh` (no heavy local deps).
- Semgrep excludes `insecure-file-permissions` (intentional `0o700`/`0o750`/`0o711`
  hardening) and `dynamic-urllib-use-detected` (HTTPS scheme-gated fetches of
  pinned upstream URLs; Bandit B310 skips apply). XML parsing uses `defusedxml`.
