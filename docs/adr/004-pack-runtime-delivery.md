# ADR-004: Pack Runtime and Delivery Modes

## Status

Accepted

## Context

ADR-001 required distro-packaged tools and forbade shipping scanning engines or signature databases. Users on Arch/CachyOS hit AUR-only packs (chkrootkit, maldet), broken pkexec allowlists, and install friction. Full portable mode needs vendored upstream tools without reimplementing detection (the S&D failure mode ADR-001 targets).

## Decision

oysterAV ships two delivery modes:

- **Full (default):** Private runtime at `$XDG_DATA_HOME/oysterav/runtime/{arch}/` with vendored upstream binaries and ClamAV signatures under `runtime/clamav/db/`, updated via bundled `freshclam` and official CDIFF patches.
- **Lite:** Resolve tools from system `PATH` / package managers / AUR-with-confirm (previous behavior).

Full mode vendors **upstream artifacts only**. oysterAV does not author malware signatures or custom detection engines. Runtime contents are tracked in `runtime.lock.json`.

firewall and fail2ban remain **host-integrated** (status probes only) in both modes.

## Amends

- **ADR-001:** Replace absolute "do not ship engines/signatures" with "do not implement engines; may vendor upstream engines and official Talos signatures in Full mode."

## Consequences

- Larger disk footprint (~400–750 MB with ClamAV DB)
- Works out of box without paru/AUR on Arch
- Lite builds omit runtime seed for advanced users
- CI can publish `runtime-{arch}.tar.zst` release artifacts
