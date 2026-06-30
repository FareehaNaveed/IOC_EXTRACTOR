"""AbuseIPDB enrichment client for IP reputation checks."""

from __future__ import annotations

from typing import Any, Dict

import requests
from requests.exceptions import RequestException, Timeout

from config import ABUSEIPDB_API_BASE_URL, ABUSEIPDB_API_KEY, REQUEST_TIMEOUT_SECONDS
from logger import get_logger

LOGGER = get_logger(__name__)


class AbuseIPDBClient:
    """Client wrapper for AbuseIPDB check endpoint."""

    def __init__(self, api_key: str = ABUSEIPDB_API_KEY, timeout: int = REQUEST_TIMEOUT_SECONDS) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Key": self.api_key, "Accept": "application/json"})

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Look up one IP address in AbuseIPDB and return normalized data."""
        if not self.api_key or self.api_key == "YOUR_API_KEY":
            return {
                "source": "AbuseIPDB",
                "ioc": ip_address,
                "ioc_type": "IPv4",
                "status": "skipped",
                "error": "AbuseIPDB API key not configured",
            }

        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""}
        LOGGER.info("AbuseIPDB lookup: %s", ip_address)

        try:
            response = self.session.get(ABUSEIPDB_API_BASE_URL, params=params, timeout=self.timeout)

            if response.status_code == 200:
                payload = response.json()
                data = payload.get("data", {})
                return {
                    "source": "AbuseIPDB",
                    "ioc": ip_address,
                    "ioc_type": "IPv4",
                    "status": "ok",
                    "http_status": 200,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country_code": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "raw": payload,
                }

            error_map = {
                401: "Invalid AbuseIPDB API key",
                403: "AbuseIPDB access forbidden",
                404: "AbuseIPDB endpoint not found",
                429: "AbuseIPDB rate limit exceeded",
            }
            message = error_map.get(response.status_code, "AbuseIPDB request failed")
            LOGGER.error("AbuseIPDB error for %s: %s", ip_address, message)

            return {
                "source": "AbuseIPDB",
                "ioc": ip_address,
                "ioc_type": "IPv4",
                "status": "error",
                "http_status": response.status_code,
                "error": message,
                "body": response.text,
            }

        except Timeout:
            LOGGER.exception("AbuseIPDB timeout for %s", ip_address)
            return {
                "source": "AbuseIPDB",
                "ioc": ip_address,
                "ioc_type": "IPv4",
                "status": "error",
                "error": "AbuseIPDB timeout",
            }
        except RequestException as exc:
            LOGGER.exception("AbuseIPDB network error for %s", ip_address)
            return {
                "source": "AbuseIPDB",
                "ioc": ip_address,
                "ioc_type": "IPv4",
                "status": "error",
                "error": f"AbuseIPDB network failure: {exc}",
            }
