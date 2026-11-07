# Health/debug commands and releasing

Moved from AGENTS.md. Read when diagnosing a running install or cutting a release.

## Health / debug

```bash
uv run oyst-cli doctor --json
uv run oyst-cli status assess --json
uv run oyst-cli runtime status --json
uv run oyst-cli serve --foreground   # RPC for GUI
uv run oysterav                      # GUI
```

## Releasing

Bump [`VERSION`](../../VERSION), run `python scripts/sync_version.py`, push to `main`.
See [docs/packaging/release.md](../packaging/release.md).
Installed builds compare to GitHub Releases via `oyst-cli version --check`
(and the status-bar / `updates.check` path).
