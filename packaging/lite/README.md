# oysterAV Lite

Lite builds use **system packages** only — no private runtime seed is bundled.

## Configuration

```toml
[runtime]
mode = "lite"
```

```bash
oyst-cli config set runtime.mode lite
```

There is no `OYSTAV_RUNTIME_MODE` environment variable; use config (or TOML) only.

## When to use Lite

- You already manage ClamAV, rkhunter, and Lynis via pacman/apt/dnf
- You want minimal disk usage (~no 400MB+ ClamAV signature cache in app data)
- You use AUR helpers (paru/yay) and accept per-pack confirmation dialogs

## Full vs Lite

| Feature | Full (default) | Lite |
|---------|----------------|------|
| Private runtime dir | Yes | No |
| AUR for chkrootkit/maldet | Optional fallback | Primary on Arch |
| ClamAV signatures | App-managed via freshclam | System `/var/lib/clamav` |
| Offline bootstrap | Seed zst supported | Requires network/packages |

See [ADR-004](../../docs/adr/004-pack-runtime-delivery.md).
