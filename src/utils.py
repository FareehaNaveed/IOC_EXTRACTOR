"""General utility helpers for filesystem, IO, and terminal formatting."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from config import LOGS_DIR, REPORTS_DIR

RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"


def bold(text: str) -> str:
    """Return text wrapped in ANSI bold codes."""
    return f"\033[1m{text}{RESET}"


def ensure_directories() -> None:
    """Create required output directories if they are missing."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def read_text_file(path: Path) -> str:
    """Read and validate alert text file content with robust error handling."""
    if not path.exists():
        raise FileNotFoundError(f"Alert file not found: {path}")

    content = path.read_text(encoding="utf-8", errors="replace")

    if not content.strip():
        raise ValueError(f"Alert file is empty: {path}")

    return content


def get_timestamp() -> str:
    """Return standardized UTC ISO-8601 timestamp for report records."""
    return datetime.now(timezone.utc).isoformat()
