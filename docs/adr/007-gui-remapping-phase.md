# ADR-007: GUI Remapping Phase

## Status

Accepted (supersedes [ADR-005](005-cli-production-phase.md))

## Context

ADR-005 froze GUI feature work so CLI/RPC could catch up. That foundation is now in place: RPC schema v2, audit trail, services lifecycle, fine-grained polkit helper, and a living GUI↔CLI contract. Continuing the freeze blocks high-value UX (Scan cancel, Settings Services) that already has backend support.

## Decision

1. **ADR-005 is superseded.** New GUI surfaces are allowed again under the rules below.
2. **[ADR-002](002-cli-first-gui-is-client.md) remains absolute:** the GTK app talks to security tools only via `OystClient` / `oyst-cli serve`. CI continues to grep for forbidden GUI subprocesses.
3. **CLI/RPC first (or same PR):** a widget may ship only when its CLI and RPC method already exist, or land in the same change as the CLI/RPC addition.
4. **Remapping is phased** (see [gui-contract.md](../cli/gui-contract.md) and [AGENTS.md](../../AGENTS.md)):
   - Wave 1 — Scan completeness (custom packs, `job.cancel`)
   - Wave 2 — Settings Services / Auth
   - Wave 3 — Low-risk CLI mirrors (audit, news refresh, quarantine add, tray/desktop)
   - Wave 4 — Advanced (firewall/fail2ban limited UI, setup/deep packs)

## Consequences

- Agents may implement new Settings/Scan widgets when RPC exists.
- Parity tests and gui-contract must be updated with every new GUI call site.
- Helper install and passwordless service-lifecycle grant/revoke are available in
  Settings → Services via Polkit RPC (`helper.install`, `auth.grant_service_lifecycle`,
  `auth.revoke_service_lifecycle`); CLI equivalents remain for scripting.
