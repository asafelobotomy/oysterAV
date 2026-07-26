# Attacker-sim runbook (oysterAV)

Operator-grade hostile-client exercise analogous to Fail2Ban’s multi-host
simulations — **without** privilege-escalation payloads or a full Vagrant lab.

This is **not** part of the PR-blocking `scripts/check.sh` triad. Use locally or
via the `workflow_dispatch` GitHub Action
[`.github/workflows/security-attacker-sim.yml`](../../.github/workflows/security-attacker-sim.yml).

## Quick dry-run (recommended)

From the repo root (requires `uv`):

```bash
./scripts/attacker_sim.sh --dry-run
```

This runs the security-property suites that model hostile inputs (bad RPC auth,
oversized frames, helper env scrub, concert abuse, mocked EICAR path).

## Live serve checks (manual)

1. Start RPC in a dedicated terminal:

   ```bash
   uv run oyst-cli serve --foreground
   ```

2. Wrong token (expect `auth_failed`):

   ```bash
   python - <<'PY'
   import json, socket
   from pathlib import Path
   sock = Path.home() / ".local/share/oysterav/oyst.sock"
   s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
   s.connect(str(sock))
   s.sendall(b'{"method":"setup.status","params":{},"id":1,"auth":"wrong"}\n')
   print(s.recv(4096).decode())
   PY
   ```

3. Oversized frame (expect connection close / malformed frame; server stays up):
   send more than 16 MiB without a newline, then reconnect with a valid request.

4. Helper polkit deny: invoke a privileged CLI action and cancel the polkit
   prompt — confirm the CLI/RPC reports failure closed (no partial root write).

5. Concert dry reject: `oyst-helper` / concert recipes with unknown `--recipe=`
   or empty `update-concert` must exit `2` (covered automatically in dry-run).

## Nightly marker

```bash
./scripts/attacker_sim.sh --nightly
```

Runs dry-run plus `@pytest.mark.security_nightly` (optional heavier tests).
Empty collection is treated as success.

## Out of scope

- Real privilege escalation / Atomic Red Team / ZAP against GTK
- Cross-UID peercred on a second live user account (mocked in CI instead)
- ClamAV engine fuzzing
