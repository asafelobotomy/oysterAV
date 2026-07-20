# ADR-007: GUI Remapping Phase

## Status

Accepted (supersedes [ADR-005](005-cli-production-phase.md))

## Context

ADR-005 froze GUI feature work so CLI/RPC could catch up. That foundation is now
in place: RPC schema v2, audit trail, services lifecycle, fine-grained polkit
helper, and a living GUI↔CLI contract. Continuing the freeze blocked high-value
UX that already had backend support.

## Decision

1. **ADR-005 is superseded.** New GUI surfaces are allowed again under the rules below.
2. **[ADR-002](002-cli-first-gui-is-client.md) remains absolute:** the GTK app talks
   to security tools only via `OystClient` / `oyst-cli serve`. CI continues to grep
   for forbidden GUI subprocesses.
3. **CLI/RPC first (or same PR):** a widget may ship only when its CLI and RPC
   method already exist, or land in the same change as the CLI/RPC addition.
4. **Remapping is phased** (living detail: [gui-contract.md](../cli/gui-contract.md),
   [AGENTS.md](../../AGENTS.md)):

| Wave | Scope | Status |
|------|-------|--------|
| 1 | Scan completeness (custom packs, `job.cancel`) | **Shipped** |
| 2 | Settings Services / Auth (helper install, passwordless grant/revoke) | **Shipped** |
| 3 | Low-risk CLI mirrors (audit, news refresh, quarantine add, tray/desktop) | **Shipped** |
| 4 | Advanced: firewall **status** + fail2ban **unban**; setup/deep packs / full firewall DSL remain **permanent CLI-first** | **Limited shipped**; residual permanent unless a future ADR reopens |

## Consequences

- Agents may implement new Settings/Scan widgets when RPC exists.
- Parity tests and gui-contract must be updated with every new GUI call site.
- Helper install and passwordless service-lifecycle grant/revoke are available in
  Settings → Services via Polkit RPC (`helper.install`, `auth.grant_service_lifecycle`,
  `auth.revoke_service_lifecycle`); CLI equivalents remain for scripting.
- Host ClamAV prevention UI (if any) must follow [ADR-008](008-clamav-host-cocontrol.md)
  and still obey CLI/RPC-first.
- Wave 4 residual (firewall rule DSL, fail2ban jail control, setup check/reset, deep
  pack CLIs) is **permanent CLI-first** — do not build a full GUI DSL without a new ADR.
