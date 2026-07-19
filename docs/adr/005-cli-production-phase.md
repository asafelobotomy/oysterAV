# ADR-005: CLI Production Phase

## Status

**Superseded by [ADR-007](007-gui-remapping-phase.md)**

## Context

oysterAV is pre-release with no production users. The CLI (`oyst-cli`) already owns all security operations (ADR-002), but workflow composition, RPC hardening, audit trails, and operator documentation lag behind what the GTK4 GUI provides as UX.

## Decision

Enter a **CLI production phase** until the CLI + RPC foundation is stable enough to re-map the GUI:

1. **All new capability** lands in `oyst_core` and `oyst_cli` first.
2. **GUI work is frozen** — bug fixes only when CLI/RPC changes break existing GUI flows; no new screens, widgets, or features.
3. **RPC schema v2** adds workflow methods (`status.assess`, `setup.run`, `runtime.bootstrap`, `audit.list`) and security hardening (peer auth, structured errors).
4. **Internal production** is the milestone — public release pipeline deferred.

## GUI freeze policy

| Allowed | Not allowed |
|---------|-------------|
| Fix regressions from CLI/RPC changes | New tabs, wizard steps, settings rows |
| Import shared logic from `oyst_core` (e.g. `health.py`) | Direct security subprocess calls (CI gate remains) |
| Update `OystClient` call sites for RPC v2 | Flatpak permission or packaging changes |

## GUI → CLI contract backlog

See [docs/cli/gui-contract.md](../cli/gui-contract.md) for the living mapping table.

Service lifecycle (`services.*`) and passwordless grants (`auth.*`) are CLI/RPC-first;
Settings toggles wait for unfreeze (gui-contract deferred section).

## Consequences

- Operators use `oyst-cli setup run`, `status assess`, and `runtime bootstrap` instead of manual command chains.
- RPC becomes trustworthy enough for future GUI re-mapping.
- GUI parity work resumes only after this phase completes.
