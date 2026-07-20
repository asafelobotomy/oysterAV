# ADR-002: CLI-First, GUI Is Client

## Status

Accepted — **Clarified by [ADR-007](007-gui-remapping-phase.md)** (GUI freeze lifted; same-PR CLI/RPC allowed)

## Context

S&D embedded scan logic in a 13k-line GUI with no scriptable CLI parity.

## Decision

`oyst-cli` owns all security operations. `oysterav` GUI uses `OystClient` over
`oyst-cli serve` only. No direct subprocess calls to security binaries from
`oysterav/`.

New GUI surfaces require matching CLI and RPC **already present or landing in the
same change** (ADR-007). Features must remain scriptable via `oyst-cli`.

## Consequences

- Every security capability is reachable from the CLI (or ships CLI+RPC with the GUI)
- CI grep gate blocks security subprocess in the GUI package
- Headless installs ship `oyst-cli` without GTK deps
