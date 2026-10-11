"""clamdscan client side: clamd endpoint discovery, client conf, argv, PING.

clamdscan reads its socket from a clamd conf; it has no ``--socket`` flag and
ignores clamscan-only options (``-r``, ``--database``, ``--exclude-dir``,
limits). Prefer the host conf; fall back to a private conf naming only the
discovered ``LocalSocket``.
"""

from __future__ import annotations

import contextlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from oyst_core.config_io import data_dir
from oyst_core.packs.clamd_onaccess import discover_clamd_conf_paths
from oyst_core.privileged.runner import run_command

CLAMD_SOCKETS = (
    "/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/var/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.sock",
    "/run/clamd.scan/clamd.sock",
)

CLIENT_CONF_NAME = "clamdscan.conf"

_SOCKET_KEY_RE = re.compile(r"^(LocalSocket|TCPSocket)\s+(\S.*?)\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ClamdEndpoint:
    """Where clamdscan should connect; ``conf`` is a readable host conf."""

    conf: Path | None = None
    local_socket: str | None = None
    tcp: bool = False

    @property
    def found(self) -> bool:
        return self.local_socket is not None or self.tcp


def parse_socket_keys(text: str) -> tuple[str | None, bool]:
    """Return (LocalSocket, has TCPSocket) from a clamd conf body.

    ClamAV 1.5 allows inline ``# comments``; strip them like the daemon does.
    """
    local: str | None = None
    tcp = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        match = _SOCKET_KEY_RE.match(line)
        if not match:
            continue
        if match.group(1).lower() == "localsocket":
            local = match.group(2)
        else:
            tcp = True
    return local, tcp


def discover_endpoint() -> ClamdEndpoint:
    """Host conf with a socket setting first, then well-known socket paths."""
    for path in discover_clamd_conf_paths():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        local, tcp = parse_socket_keys(text)
        if local or tcp:
            return ClamdEndpoint(conf=path, local_socket=local, tcp=tcp)
    for sock in CLAMD_SOCKETS:
        if Path(sock).exists():
            return ClamdEndpoint(local_socket=sock)
    return ClamdEndpoint()


def _write_private_conf(local_socket: str) -> Path:
    """Write a 0600 conf holding only ``LocalSocket`` (never follows symlinks)."""
    if "\n" in local_socket or "\r" in local_socket:
        raise ValueError("invalid clamd socket path")
    target = data_dir() / CLIENT_CONF_NAME
    # mkstemp: O_EXCL + 0600 + random name; os.replace never follows a symlink.
    fd, tmp = tempfile.mkstemp(prefix=f".{CLIENT_CONF_NAME}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f"LocalSocket {local_socket}\n")
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return target


def client_conf(endpoint: ClamdEndpoint) -> Path | None:
    """Conf path for ``clamdscan --config-file``; None when no endpoint is known."""
    if endpoint.conf is not None:
        return endpoint.conf
    if endpoint.local_socket:
        return _write_private_conf(endpoint.local_socket)
    return None


def clamdscan_argv(
    binary: str,
    target: str,
    *,
    multiscan: bool = False,
    endpoint: ClamdEndpoint | None = None,
) -> list[str]:
    """Build clamdscan argv; raises FileNotFoundError when clamd can't be located."""
    ep = endpoint if endpoint is not None else discover_endpoint()
    conf = client_conf(ep)
    if conf is None:
        raise FileNotFoundError("clamd socket not found")
    argv = [binary, f"--config-file={conf}", "--stdout"]
    if ep.local_socket:
        # clamd runs as its own user; pass our open fd so it can read $HOME.
        argv.append("--fdpass")
    if multiscan:
        argv.append("--multiscan")
    argv.append(target)
    return argv


def clamd_ping(binary: str, endpoint: ClamdEndpoint | None = None) -> bool:
    """True when clamd answers PING through the same conf a scan would use."""
    ep = endpoint if endpoint is not None else discover_endpoint()
    try:
        conf = client_conf(ep)
        if conf is None:
            return False
        res = run_command([binary, f"--config-file={conf}", "--ping", "1"], timeout=15)
    except (ValueError, OSError):
        return False
    return res.returncode == 0
