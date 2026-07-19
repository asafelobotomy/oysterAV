# ADR-002: CLI-First, GUI Is Client

## Status

Accepted

## Context

S&D embedded scan logic in a 13k-line GUI with no scriptable CLI parity.

## Decision

`oyst-cli` owns all security operations. `oysterav` GUI uses `OystClient` over `oyst-cli serve` only. No direct subprocess calls to security binaries from `oysterav/`.

## Consequences

- Every feature must exist in CLI first
- CI grep gate blocks security subprocess in GUI package
- Headless installs ship `oyst-cli` without GTK deps
