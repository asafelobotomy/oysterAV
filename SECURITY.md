# Security policy

## Supported versions

Security fixes land on the default branch (`main`) and ship in the next release.
Older release tags are not generally backported unless a critical issue warrants
a hotfix tag.

| Version | Supported |
|---------|-----------|
| Latest release on GitHub | Yes |
| Prior tags | Best-effort only |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs that could enable
privilege escalation, auth bypass, or remote/local code execution via oysterAV’s
RPC, polkit helper, or host co-control paths.

Prefer one of:

1. **GitHub Security Advisories** — [Report a vulnerability](https://github.com/asafelobotomy/oysterAV/security/advisories/new) on this repository (private report to maintainers).
2. If advisories are unavailable, email the maintainer contact listed on the [GitHub profile](https://github.com/asafelobotomy) with subject `oysterAV security` and enough detail to reproduce (version/`VERSION`, OS, steps, impact).

We aim to acknowledge reports within **7 days** and to share a remediation plan
or clarifying questions soon after. Coordinated disclosure: please wait until a
fix is released (or we explicitly agree) before public write-ups.

## Scope hints

In-scope examples: polkit/`oyst-helper` argv validation, RPC token/socket
handling, passwordless auth-grant scope, ClamAV co-control conf mutations that
could escalate or DoS, supply-chain issues in published artifacts.

Out of scope for routine reports: theoretical issues requiring already-root
access; third-party ClamAV/kernel fanotify limitations; AUR helper password
prompts outside oysterAV’s polkit policy.

## Hardening notes

Operators who change helper policy or helper text should re-run:

```bash
oyst-cli install-privileged-helper
```

Passwordless service-lifecycle grants (`systemctl-up` + `maldet-config` only) require
a working systemd expire timer; grant installation fails closed if the timer cannot
be installed. TTL is 7 days (`auth.status` reports `expire_timer_installed`).

See also `docs/security/` for audit notes when present.
