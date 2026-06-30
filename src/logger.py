"""Application-wide logging configuration."""

from __future__ import annotations

import logging

from config import LOG_FILE_PATH
from utils import ensure_directories


def _configure_root_logger() -> None:
    """Configure root logging handlers for file and console output."""
    ensure_directories()

    if logging.getLogger().handlers:
        return

    file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger instance for modules in this project."""
    _configure_root_logger()
    return logging.getLogger(name)
