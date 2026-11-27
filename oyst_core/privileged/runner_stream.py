"""Run a long scanner line by line: report each stdout line, keep only the lines that matter.

clamscan prints one ``<path>: OK`` line per file. A home scan can print millions of them, so
holding the whole stdout costs hundreds of MB and gives no progress until the end. Here each
line goes to ``on_line`` as it arrives and only lines that ``keep`` accepts are returned.
"""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from typing import IO

from oyst_core.privileged.runner import (
    ALLOWED_COMMANDS,
    CommandResult,
    _command_basename,
    scrubbed_env_for_argv,
)


def _pump(stream: IO[str], sink: Callable[[str], None]) -> None:
    for line in stream:
        sink(line.rstrip("\n"))


def run_command_streaming(
    argv: Sequence[str],
    *,
    on_line: Callable[[str], None],
    keep: Callable[[str], bool],
    timeout: int = 3600,
    should_cancel: Callable[[], bool] | None = None,
    poll: float = 1.0,
    grace: float = 5.0,
) -> CommandResult:
    """Like run_command_cancellable, but stdout is streamed: ``on_line`` sees every line,
    and the result's stdout holds only the lines ``keep`` accepted (in order)."""
    if not argv:
        raise ValueError("empty argv")
    base = _command_basename(argv)
    if base not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowlisted: {base}")
    proc = subprocess.Popen(  # noqa: S603 — allowlisted argv, no shell
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="backslashreplace",
        env=scrubbed_env_for_argv(argv),
    )
    kept: list[str] = []
    err: list[str] = []

    def take(line: str) -> None:
        try:
            on_line(line)
        except Exception:  # noqa: BLE001 — a progress hook never breaks a scan
            pass
        if keep(line):
            kept.append(line)

    assert proc.stdout is not None and proc.stderr is not None
    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, take), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err.append), daemon=True),
    ]
    for t in readers:
        t.start()
    deadline = time.monotonic() + timeout
    stopped: str | None = None
    while proc.poll() is None:
        if should_cancel is not None and should_cancel():
            stopped = "cancel"
        elif time.monotonic() >= deadline:
            stopped = "timeout"
        if stopped:
            proc.terminate()
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            break
        try:
            proc.wait(timeout=poll)
        except subprocess.TimeoutExpired:
            pass
    for t in readers:
        t.join(timeout=grace)
    return CommandResult(proc.returncode, "\n".join(kept), "\n".join(err), stopped=stopped)
