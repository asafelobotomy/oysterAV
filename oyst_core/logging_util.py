"""Persistent CLI logging."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from oyst_core.config import data_dir

LOG_PATH = data_dir() / "oyst-cli.log"
MAX_BYTES = 5 * 1024 * 1024


def setup_logging(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("oyst-cli")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=MAX_BYTES, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    stream = logging.StreamHandler()
    stream.setLevel(logging.WARNING)
    logger.addHandler(stream)
    return logger
