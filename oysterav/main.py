"""oysterAV GUI entry."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv if argv is None else argv)
    try:
        from oysterav.gui.app import OysterApp
    except ImportError as exc:
        print(
            "oysterAV GUI requires GTK4: install with uv sync --extra gui",
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    start_minimized = "--minimized" in args
    cleaned = [args[0], *[a for a in args[1:] if a != "--minimized"]]
    app = OysterApp(start_minimized=start_minimized)
    sys.exit(app.run(cleaned))


if __name__ == "__main__":
    main()
