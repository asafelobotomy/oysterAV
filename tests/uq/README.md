Tests for oysterAV's Security page in uQ Settings (`uq/pages/oysterav-security/`).

```
logic.test.mjs     Node: logic.js, page.toml, and what the QML may send   node --test 'tests/uq/*.test.mjs'
load-logic.mjs     loads logic.js (no Qt calls in it) for Node
toml-lite.mjs      the small TOML reader the Node tests use for page.toml
tst_*.qml          QML: the page, tab by tab, against a fake ctx (needs Qt 6; CI runs it)
PageHarness.qml    what the QML tests share: the page in a Loader, a fake ctx answering every command from fixtures/
stub/ FakeContext.qml tst_components.qml
                   the page test kit of uQ at the commit pinned in .github/workflows/ci.yml (uq_api 3,
                   templates/settings-page-tests/), unchanged. Refresh them when moving to a newer uQ.
fixtures/          what the real `oyst-cli` commands print (see below)
```

Run the QML tests offscreen (`/usr/lib/qt6/bin/qmltestrunner` on Arch, from `qt6-declarative`; Debian and
Ubuntu also need `qml6-module-qtquick-dialogs` for the folder dialog). `QML_XHR_ALLOW_FILE_READ` lets
the tests read `fixtures/`:

```
QML_XHR_ALLOW_FILE_READ=1 QT_QPA_PLATFORM=offscreen qmltestrunner -import tests/uq/stub -input tests/uq
```

Check the folder itself with uQ's own checker, built from the commit pinned in CI:

```
uqctl integrations check --no-programs uq/
```

## Fixtures

`fixtures/*.json` are the real output of each `oyst-cli` command the page runs, recorded from a home with one
scan in the history, one quarantined file and one audit entry. `tests/test_cli/test_uq_fixtures.py` runs the
commands again and fails when a fixture's keys or value types no longer match, so the page tests can't drift
from the CLI. After changing a command's output:

```
UPDATE_FIXTURES=1 uv run pytest tests/test_cli/test_uq_fixtures.py
```

The CLI side of the page (`config show|set`, the `--dry-run --json` plans, `scan --ndjson`) is tested in
`tests/test_cli/test_uq_page_contract.py`; that every declared argv parses to a real command, and that the
argument patterns refuse options, is in `tests/test_cli/test_uq_integration.py`.
