# GUI remapping status (ADR-007)

Moved from AGENTS.md. Read before adding or changing a GUI surface, or deciding whether something stays CLI-only.

Waves 1–5 are shipped (Shield: structured firewall + fail2ban jail/unban).
**Permanent CLI-first remainder** (no full GUI DSL): setup check,
`firewall plan` / nftables mutation, deep pack CLIs (`fangfrisch`, `lynis audit`,
etc.). Helper install and auth grant/revoke are GUI Install button + passwordless
toggle via Polkit RPC (`helper.install` / `auth.grant_service_lifecycle`).
Catalogued in [docs/cli/gui-contract.md](../cli/gui-contract.md); parity
enforced by `tests/test_cli/test_gui_cli_parity.py`.

ADR-008 Phase 4–4.1 host co-control (`clamonacc ensure-fdpass` /
`ensure-prevention`, `virusevent ensure`, `clamav ensure-disable-cache`) are
CLI/RPC + thin Real-time GUI. DisableCache Ensure is on the setup wizard Harden
page and CLI/health (not a Settings Real-time button).

See also [docs/adr/007-gui-remapping-phase.md](../adr/007-gui-remapping-phase.md).
