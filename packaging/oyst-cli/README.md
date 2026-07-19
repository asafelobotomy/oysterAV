# oyst-cli headless package

Install CLI only (no GTK):

```bash
uv sync
```

After `uv sync`, the `oyst-cli` entry point is available via `uv run oyst-cli` (or the project venv’s `bin/`).

Editable install is only needed if you are not using uv’s project environment:

```bash
uv pip install -e .
```
