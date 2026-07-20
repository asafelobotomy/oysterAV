# ADR-003: Pack Tier Policy

## Status

Accepted

## Context

Users need clarity on required vs optional security tools.

## Decision

Packs are tiered:

- **required**: clamav, freshclam — scans fail without these
- **recommended**: rkhunter, chkrootkit, lynis, clamonacc, firewall
- **optional**: maldet, unhide, fail2ban, fangfrisch — enhance coverage when present

`oyst-cli doctor` reports tier, version gates, and install hints per distro.

`fangfrisch` refreshes unofficial ClamAV signature providers into the ClamAV DB
directory **after** official freshclam CVD updates. It never replaces freshclam.

See also [ADR-006](006-dependency-scope.md) for skip/defer policy (YARA, AIDE, HIDS)
and [ADR-008](008-clamav-host-cocontrol.md) for clamonacc / host ClamAV co-control.

## Consequences

- Orchestrated scans degrade gracefully for missing optional packs
- Required pack absence returns exit code 5
