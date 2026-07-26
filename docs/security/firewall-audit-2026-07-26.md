# Firewall process audit — 2026-07-26

Findings-first review of oysterAV firewall install, wizard backend choice, soft-swap,
and mutation safety. Remediation landed in Waves 1–3 (this document).

**Threat model:** local same-UID misuse / misconfiguration on a wheel desktop;
SSH lockout from remote sessions; dual-manager soft-swap leaving both off.

## How it works

Detect → install (optional) → select / soft-swap → ensure → mutate via helper.
Wizard Auto-Install / Harden fold firewall into one `setup-concert` /
`setup-harden` argv (`--install-firewall` / `--select-firewall`). Shield toggle
uses preference-aware ensure; rule edits require GUI confirm.

## Findings table

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| **F1** | High | Soft-swap stops peer before target enable; enable fail → both off | **Fixed** — peer restart on enable failure |
| **FW-01** | High | Wizard Auto-Install / Harden: concert then separate `firewall.select` (second polkit) | **Fixed** — single concert + `--firewall-backend` |
| **F2 / FW-02** | Med | Saves `firewall.managed_backend` when select fails | **Fixed** — config_set only on success |
| **FW-03** | Med | Root `--with-firewall` ignored managed_backend (UFW-first) | **Fixed** — prefer/recommend + userspace resolve→select |
| **F3** | Med | firewalld rich rules can drop/reject SSH with no gate | **Fixed** — require `--force-lockout-risk` |
| **F4 / FW-05** | Med | Wizard Apply / Shield routine rule add skip confirm; `_expect_managed` dead | **Fixed** |
| **FW-04** | Med | Host shield vs Shield for `nft-direct` wording | **Fixed** — Dashboard Partial · managed off |
| **FW-06** | Low | No SSH guard on firewalld remove-service ssh / remove port 22 | **Fixed** |
| **FW-08** | Low | Harden “include firewall” switch not feeding concert | **Fixed** — wired via `firewall_backend` |
| **FW-09–12** | Low | Detect cache / nft warn / CLI parity | **Mitigated** — invalidate on mutate; CLI `--firewall-backend`; nft confirm copy |
| **F9** | Info | No `.bak` rollback of firewall config | **Accepted** — hash audit + export; manual restore |

## Operator notes

- After helper lifecycle changes: `oyst-cli install-privileged-helper`.
- Risky SSH mutations need `--force-lockout-risk` (CLI) or the GUI force confirm.
- Setup: `oyst-cli setup run --firewall-backend=ufw|firewalld|none --confirm`.

## Validation

```bash
./scripts/check.sh --quick
uv run pytest -m security tests/test_security/test_firewall_security_props.py \
  tests/test_security/test_helper_fw_lifecycle.py -q --no-cov
```
