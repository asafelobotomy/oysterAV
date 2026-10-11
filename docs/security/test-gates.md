# Security verification gates (oysterAV)

Commit-time gates for privileged surfaces. Mapped loosely to **OWASP ASVS 5.0**
automatable controls (not a Level 2 certification claim). Full requirement map:
[`asvs-checklist.md`](asvs-checklist.md).

## Gates

| Gate | Command / location | Control |
|------|--------------------|---------|
| Security marker suite | `uv run pytest -m security -q --no-cov` | Validation, helper argv, firewall props, RPC auth/framing, audit redaction |
| Security module coverage ≥85% | `uv run python scripts/check_security_coverage.py` | Regressions in privileged modules cannot drop below floor |
| Bandit MEDIUM+ | `uv tool run --python 3.12 bandit==1.9.4 -c bandit.yaml -r oyst_core oyst_cli -ll -ii`; fails unless output reports `Files skipped (0)` | SAST (injection / unsafe subprocess patterns) |
| pip-audit | `uv export --frozen --all-extras --no-emit-project -o req.txt` then `uv tool run pip-audit==2.10.1 -r req.txt --require-hashes --disable-pip` | Known CVEs in the project's locked dependencies (`uv.lock`) |
| Gitleaks | `.github/workflows/security-scan.yml` | Secrets in git history / working tree |
| Semgrep | `.github/workflows/security-scan.yml` (`p/python`, `p/security-audit`) | Additional SAST on `oyst_core` / `oyst_cli` |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` (blocking) | Supply-chain / repo hygiene score |
| GUI subprocess ban | CI `rg` + `test_no_security_subprocess_in_gui` | ADR-002: GUI uses `OystClient` only |
| Global coverage | `fail_under = 65` in `pyproject.toml` | Broader quality (not a security floor) |

`scripts/check.sh` and GitHub CI run the security marker suite, security coverage,
Bandit, and pip-audit after the usual triad. Tool versions are pinned identically
in both places; bump them together.

- **Bandit** must run on Python ≥3.12: older interpreters cannot parse PEP 695
  syntax and Bandit silently *skips* such files while still exiting 0. The gate
  therefore also fails when any file is skipped.
- **pip-audit** audits an export of `uv.lock` (with hashes, no resolver), not the
  ambient environment. Running bare `uv tool run pip-audit` only audits
  pip-audit's own tool venv and never sees oysterAV's dependencies.
- **Semgrep** runs in `semgrep/semgrep` pinned by tag and image-index digest;
  Dependabot does not track job containers, so bump it manually.

## ASVS-oriented mapping

| Theme | Evidence in tests |
|-------|-------------------|
| Input validation / injection | `test_validators_adversarial`, `test_helper_argv_injection`, `test_helper_services_argv`, `test_helper_seal_install_adversarial`, `test_quarantine_refuse`, `test_wave2_privilege`; golden `Case`/`Expect` in `corpora.py` |
| Privilege / command construction | `test_helper_fw_lifecycle`, `test_helper_env_argc`, firewall security props |
| Concert workflow abuse | `test_concert_abuse` (ASVS V11.1) |
| Local RPC authentication / framing / DoS bounds | `test_rpc_auth_hardening`, `test_rpc_adversarial`, `test_rpc_dos_bounds` |
| Detection-path smoke | `test_eicar_detection_path` (mocked; live via `OYST_EICAR_LIVE=1`) |
| Sensitive logging | `test_audit_redaction` |
| Attacker-sim (optional) | [`attacker-sim.md`](attacker-sim.md), `scripts/attacker_sim.sh`, `workflow_dispatch` |
| Requirement-level map | [`asvs-checklist.md`](asvs-checklist.md) |

## Live EICAR (optional)

```bash
OYST_EICAR_LIVE=1 uv run pytest -m security tests/test_security/test_eicar_detection_path.py -q --no-cov
```

Requires host `clamscan` on `PATH`. Default CI uses the mocked path only.

## Attacker-sim (non-blocking)

```bash
./scripts/attacker_sim.sh --dry-run
# or: GitHub Actions → Security attacker-sim → Run workflow
```

## How to add a security test

1. Put it under `tests/test_security/`.
2. Mark with `@pytest.mark.security` (or use shared `corpora.py`).
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
  (see checklist chapter-level `n/a` and priority gaps).
- Peercred cross-UID is covered via mocked `SO_PEERCRED` (no live cross-UID socket).
- Same-process RPC local fallback skips token (documented `partial` in checklist).
- Dependency CVE exceptions (if ever needed) go in
  [`dependency-exceptions.md`](dependency-exceptions.md) with an expiry note.
- Gitleaks/Semgrep run in GitHub Actions (`security-scan.yml`); they are not
  duplicated in `scripts/check.sh` (no heavy local deps).
- Semgrep excludes `insecure-file-permissions` (intentional `0o700`/`0o750`/`0o711`
  hardening) and `dynamic-urllib-use-detected` (HTTPS scheme-gated fetches of
  pinned upstream URLs; Bandit B310 skips apply). XML parsing uses `defusedxml`.
