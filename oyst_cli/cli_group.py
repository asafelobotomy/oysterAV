"""Root Click group: stable exit codes and finish logging for every run."""

from __future__ import annotations

import logging
import sys
from collections.abc import Sequence
from typing import Any

import click

from oyst_core.models import ExitCode

_LOG = logging.getLogger(__name__)

_NOISE_ARGS = frozenset({"-v", "--verbose"})


def _exit_code_from(code: object) -> int:
    """Normalize a ``SystemExit.code`` / Click exit code to an int."""
    if code is None:
        return int(ExitCode.SUCCESS)
    if isinstance(code, int):
        return code
    # sys.exit("message") prints the message and exits 1 in CPython; keep 1 out
    # of the error path because 1 means "threats found" for oyst-cli.
    click.echo(str(code), err=True)
    return int(ExitCode.ERROR)


def _cli_label(args: Sequence[str]) -> str:
    parts = [a for a in args if a not in _NOISE_ARGS]
    return " ".join(["cli", *parts]) if parts else "cli"


def _is_terminal_mgmt(args: Sequence[str]) -> bool:
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg == "terminal"
    return False


def _log_finish(args: Sequence[str], code: int) -> None:
    if _is_terminal_mgmt(args):
        return
    try:
        from oyst_core.terminal_log import log_structured

        label = _cli_label(args)
        log_structured(
            "cli",
            "cli.finish",
            f"{label} finished (exit {code})",
            {"exit_code": code},
        )
    except Exception:  # noqa: BLE001
        pass


class OystGroup(click.Group):
    """Map ClickException / uncaught errors to ``ExitCode.ERROR`` (not 1).

    Click usage errors keep their exit code 2. ``SystemExit`` codes raised by
    commands pass through unchanged and are logged as the real exit code.
    """

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        **extra: Any,
    ) -> Any:
        if not standalone_mode:
            return super().main(args, prog_name, complete_var, standalone_mode=False, **extra)
        argv = list(sys.argv[1:] if args is None else args)
        code = self._run(argv, prog_name, complete_var, **extra)
        _log_finish(argv, code)
        sys.exit(code)

    def _run(
        self,
        argv: list[str],
        prog_name: str | None,
        complete_var: str | None,
        **extra: Any,
    ) -> int:
        try:
            rv = super().main(argv, prog_name, complete_var, standalone_mode=False, **extra)
        except click.UsageError as exc:
            exc.show()
            return exc.exit_code
        except click.ClickException as exc:
            exc.show()
            return int(ExitCode.ERROR)
        except click.Abort:
            click.echo("Aborted!", err=True)
            return int(ExitCode.ERROR)
        except SystemExit as exc:
            return _exit_code_from(exc.code)
        except Exception as exc:  # noqa: BLE001
            _LOG.exception("unhandled oyst-cli error")
            click.echo(f"Error: {type(exc).__name__}: {exc}", err=True)
            return int(ExitCode.ERROR)
        return rv if isinstance(rv, int) and not isinstance(rv, bool) else 0
