"""Centralized configuration for IOC extractor project."""

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

REPORT_JSON_PATH = REPORTS_DIR / "report.json"
REPORT_CSV_PATH = REPORTS_DIR / "report.csv"
LOG_FILE_PATH = LOGS_DIR / "application.log"

BENIGN_ALERT_FILE = BASE_DIR / "benign_alert.txt"
MALICIOUS_ALERT_FILE = BASE_DIR / "malicious_alert.txt"
ALERT_FILES = [BENIGN_ALERT_FILE, MALICIOUS_ALERT_FILE]

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# Add your API keys before running live enrichment.
VT_API_KEY = "your_api_key"
ABUSEIPDB_API_KEY = "your_api_key"

REQUEST_TIMEOUT_SECONDS = 12
