"""Start ``oyst-cli serve`` as its own process for GUI clients.

The backend must not live inside the GTK process: scans, installs and Polkit
prompts belong to oyst-cli (ADR-002), and a running job must survive the GUI
being closed. The spawned server detaches into its own session and exits on its
own after ``idle_exit`` seconds without connections or an active job.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from oyst_core.config import data_dir

DEFAULT_IDLE_EXIT_SEC = 900.0


def serve_log_path() -> Path:
    return data_dir() / "serve.log"


def _site_root() -> str:
    import oyst_core

    return str(Path(oyst_core.__file__).resolve().parent.parent)


def serve_argv(socket_path: Path, *, idle_exit: float = DEFAULT_IDLE_EXIT_SEC) -> list[str]:
    """argv that runs ``oyst-cli serve`` with this interpreter and this oyst_core."""
    code = (
        "import sys; "
        f"sys.path.insert(0, {_site_root()!r}); "
        "from oyst_cli.main import cli; "
        f"cli(['serve', '--socket', {str(socket_path)!r}, '--idle-exit', {str(idle_exit)!r}])"
    )
    # -I: ignore PYTHON* env, cwd and user site; the explicit insert pins oyst_core.
    return [sys.executable, "-I", "-c", code]


def spawn_rpc_server(socket_path: Path, *, idle_exit: float = DEFAULT_IDLE_EXIT_SEC) -> None:
    log_path = serve_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    log_fd = os.open(str(log_path), flags, 0o600)
    try:
        os.fchmod(log_fd, 0o600)
        subprocess.Popen(  # noqa: S603 — fixed argv, own interpreter
            serve_argv(socket_path, idle_exit=idle_exit),
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=log_fd,
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
    finally:
        os.close(log_fd)


__all__ = ["DEFAULT_IDLE_EXIT_SEC", "serve_argv", "serve_log_path", "spawn_rpc_server"]
