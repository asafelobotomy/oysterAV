# ADR-001: Orchestrator Not Engine

## Status

Accepted — **Amended by [ADR-004](004-pack-runtime-delivery.md)**

## Context

Search & Destroy failed by reimplementing detection engines (ML, heuristics, custom watchdog).

## Decision

oysterAV orchestrates mature system tools (ClamAV, rkhunter, Lynis, etc.) via thin pack adapters. We do not **implement** signature databases or scanning engines in application code.

In **Full mode** (ADR-004), we may **vendor upstream** engines and official ClamAV CVD databases into a private runtime directory. In **Lite mode**, tools are resolved from the host system.

## Consequences

- Depends on distro-packaged security tools in Lite mode; private runtime in Full mode
- Smaller application codebase, faster delivery
- Detection quality follows upstream tools
