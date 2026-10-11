"""Persistent CLI logging."""

from __future__ import annotations

import logging
import os
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler

from oyst_core.config import data_dir

LOG_PATH = data_dir() / "oyst-cli.log"
MAX_BYTES = 5 * 1024 * 1024


class PrivateRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler whose (re)opened log files are always mode 0600."""

    def _open(self) -> TextIOWrapper:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.baseFilename, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        return open(fd, "a", encoding=self.encoding, errors=self.errors)  # noqa: SIM115


def setup_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("oyst-cli")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = PrivateRotatingFileHandler(LOG_PATH, maxBytes=MAX_BYTES, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    try:
        os.chmod(LOG_PATH, 0o600)
    except OSError:
        pass
    stream = logging.StreamHandler()
    stream.setLevel(logging.WARNING)
    logger.addHandler(stream)
    return logger
