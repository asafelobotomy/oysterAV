# ADR-005: CLI Production Phase

## Status

**Superseded by [ADR-007](007-gui-remapping-phase.md)** — retained for history only.
**Do not apply the GUI freeze.** New GUI work follows ADR-007 + ADR-002.

## Context (historical)

At the time of this ADR, oysterAV was pre-release: the CLI (`oyst-cli`) already
owned security operations (ADR-002), but workflow composition, RPC hardening,
audit trails, and operator documentation lagged the GTK4 GUI.

## Decision (historical)

Enter a **CLI production phase** until the CLI + RPC foundation was stable enough
to re-map the GUI:

1. **All new capability** landed in `oyst_core` and `oyst_cli` first.
2. **GUI work was frozen** — bug fixes only when CLI/RPC changes broke existing
   GUI flows; no new screens, widgets, or features.
3. **RPC schema v2** added workflow methods (`status.assess`, `setup.run`,
   `runtime.bootstrap`, `audit.list`) and security hardening (peer auth,
   structured errors).
4. **Internal production** was the milestone — public release pipeline deferred.

## GUI freeze policy (obsolete)

| Allowed (then) | Not allowed (then) |
|----------------|--------------------|
| Fix regressions from CLI/RPC changes | New tabs, wizard steps, settings rows |
| Import shared logic from `oyst_core` | Direct security subprocess calls (CI gate remains under ADR-002) |
| Update `OystClient` call sites for RPC v2 | Flatpak permission or packaging changes |

## GUI → CLI contract

See [docs/cli/gui-contract.md](../cli/gui-contract.md) for the living mapping
table (still authoritative under ADR-007).

## Consequences (historical → current)

- Operators use `oyst-cli setup run`, `status assess`, and `runtime bootstrap`
  instead of manual command chains — still true.
- RPC became trustworthy enough for GUI remapping — completed; see ADR-007.
- GUI parity work resumed under ADR-007 (waves 1–3 + limited wave 4 shipped).
