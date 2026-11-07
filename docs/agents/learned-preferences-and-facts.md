# Learned user preferences and workspace facts

Moved from AGENTS.md. Read before designing or changing GUI/UX behaviour, privileged flows, setup/wizard behaviour, or when product background is needed.

## Learned User Preferences

- Prefer CLI/RPC surfaces first for new features; wire the GUI only after matching commands exist.
- Prefer a detailed plan before implementing large multi-surface or security-sensitive changes; for audits, deliver findings-only reports first and remediate only after a separate approved plan.
- Prefer recognizing host-installed tools as installed (system vs private runtime) without forcing a pack reinstall.
- Prefer a single password/auth prompt at the start of each user-initiated action (Privilege Concert), including multi-pack scans, hardenings, Update all, and bulk resolve/quarantine—not mid-flow or per-item prompts; order disclosed steps by priority.
- Prefer Settings options that autosave; avoid redundant Save buttons when individual controls already persist.
- Prefer a lean GUI that does not duplicate Settings controls onto Scan or other tabs; bulk Update/Apply/Install All actions should use one collapsible itemized checklist with per-item controls (no duplicate lists). On Scan, use pack cards as the sole pack-inclusion/status surface (profile-driven mute for unused packs; Custom uses on-card checkboxes)—no separate pack list above the cards.
- Prefer distro-portable host integration over distro-specific one-offs.
- Prefer host co-control that works in concert with the host (surgical drop-ins / ensure-*); never wholesale override of host ClamAV or daemon config.
- Prefer first-run/setup wizard auto-application of safe surgical hardenings; leave path-scoped on-access prevention for Real-time after the user chooses paths.
- Prefer SSH-safe checks before enabling UFW/firewalld during setup/wizard flows.
- Prefer user-facing system and status messages without developer notes or internal implementation jargon; Scan pack cards should briefly explain each pack's role and active/pending/complete state in plain language.
- Prefer GUI chrome that keeps a stable default window size: primary pages (especially Scan) should fit without scrollbars, pack-card content should stay fully visible by enlarging cards within that height budget (not by lengthening the page), and optional UI (news ticker) or post-action refreshes must not change status-bar or window height.

## Learned Workspace Facts

- oysterAV is a from-scratch successor to deprecated xanadOS Search & Destroy (https://github.com/asafelobotomy/xanadOS-Search_Destroy).
- Repository license is GPLv3.
- Default GUI themeing target is Gruvbox Dark Hard via a shared theme/color library.
- Status-bar oysterAV GitHub Release and pack/service update notices take priority over the security-news ticker.
- Security-news ticker freshness is configurable in Settings (7/14/30 days; default 14).
- Privileged-helper install refuses to embed a user-writable oysterAV checkout; `oyst_core` must live under a root-owned prefix (distro package or root install), which matters on externally-managed Python distros (e.g. Arch/CachyOS).
- Privilege Concert ([ADR-009](../adr/009-privilege-concert.md)) is the unified single-admin-auth-per-user-action model for privileged multi-step flows (scans, setup hardenings, Update all / update-concert, resolve, bulk install).
- Dashboard is a quick-glance pressing-posture surface across protection layers (not ClamAV-only and not a per-pack catalog).
- Settings Terminal is a persistent shared CLI/GUI session transcript: structured by default with an optional raw/advanced view, ring-buffer retention, Clear-only wipe, and export.
