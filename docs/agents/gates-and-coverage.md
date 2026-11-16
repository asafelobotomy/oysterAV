# Quality gates and coverage

Moved from AGENTS.md. Read when judging what a test or gate proves, or touching coverage settings.

Coverage: `pytest` measures `oyst_core` + `oyst_cli` (branch on) with
`fail_under` in [pyproject.toml](../../pyproject.toml). `oysterav` is **not** in the
coverage source list — GUI quality is enforced by parity +
`oysterav/gui/rpc_actions.py` unit tests, not line %.

| Gate | What it proves |
|------|----------------|
| `scripts/check_loc.py` | Production files ≤400 lines (or within frozen allowlist ceiling) |
| `test_gui_cli_parity` / `test_rpc_parity` | Every GUI/`RpcServer` method has a CLI command (existence) |
| `tests/test_core/test_rpc_actions.py` | ADR-007 GUI actions call the right `OystClient` methods |
| Unit tests under `tests/test_core/` | Behavioral logic (mocks; no real scanners) |
| CLI smoke / `--help` | Command registration and confirm gates |

