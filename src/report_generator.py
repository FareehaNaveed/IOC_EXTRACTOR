"""Generate JSON and CSV reports for IoC processing results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Tuple

import pandas as pd

from config import REPORT_CSV_PATH, REPORT_JSON_PATH
from logger import get_logger
from utils import ensure_directories

LOGGER = get_logger(__name__)


def generate_reports(rows: Iterable[dict]) -> Tuple[Path, Path]:
    """Write report records to JSON and CSV outputs under the reports directory."""
    ensure_directories()

    rows_list = list(rows)

    with REPORT_JSON_PATH.open("w", encoding="utf-8") as json_file:
        json.dump(rows_list, json_file, indent=2)

    dataframe = pd.DataFrame(rows_list)
    dataframe.to_csv(REPORT_CSV_PATH, index=False)

    LOGGER.info("Report generation complete: %s, %s", REPORT_JSON_PATH, REPORT_CSV_PATH)
    return REPORT_JSON_PATH, REPORT_CSV_PATH
