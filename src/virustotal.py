"""VirusTotal enrichment client for IOC lookups."""

from __future__ import annotations

import base64
from typing import Any, Dict

import requests
from requests import Response
from requests.exceptions import RequestException, Timeout

from config import REQUEST_TIMEOUT_SECONDS, VT_API_BASE_URL, VT_API_KEY
from logger import get_logger

LOGGER = get_logger(__name__)


class VirusTotalClient:
    """Client wrapper around VirusTotal v3 API endpoints."""

    def __init__(self, api_key: str = VT_API_KEY, timeout: int = REQUEST_TIMEOUT_SECONDS) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key})

    def _handle_response(self, response: Response, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Normalize successful and failed responses into a structured payload."""
        if response.status_code == 200:
            payload = response.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "ok",
                "http_status": 200,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "raw": payload,
            }

        error_map = {
            401: "Invalid VirusTotal API key",
            403: "VirusTotal access forbidden",
            404: "VirusTotal indicator not found",
            429: "VirusTotal rate limit exceeded",
        }
        message = error_map.get(response.status_code, "VirusTotal request failed")
        LOGGER.error("VirusTotal error for %s (%s): %s", ioc, ioc_type, message)

        return {
            "source": "VirusTotal",
            "ioc": ioc,
            "ioc_type": ioc_type,
            "status": "error",
            "http_status": response.status_code,
            "error": message,
            "body": response.text,
        }

    def _request(self, endpoint: str, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Execute a VirusTotal request with robust network and timeout handling."""
        if not self.api_key or self.api_key == "YOUR_API_KEY":
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "skipped",
                "error": "VirusTotal API key not configured",
            }

        url = f"{VT_API_BASE_URL}/{endpoint}"
        LOGGER.info("VirusTotal lookup: %s (%s)", ioc, ioc_type)

        try:
            response = self.session.get(url, timeout=self.timeout)
            return self._handle_response(response, ioc, ioc_type)
        except Timeout:
            LOGGER.exception("VirusTotal timeout for %s", ioc)
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "error",
                "error": "VirusTotal timeout",
            }
        except RequestException as exc:
            LOGGER.exception("VirusTotal network error for %s", ioc)
            return {
                "source": "VirusTotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "error",
                "error": f"VirusTotal network failure: {exc}",
            }

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Query VirusTotal IP address reputation."""
        return self._request(f"ip_addresses/{ip_address}", ip_address, "IPv4")

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal domain reputation."""
        return self._request(f"domains/{domain}", domain, "Domain")

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal file hash reputation."""
        return self._request(f"files/{file_hash}", file_hash, "FileHash")

    def lookup_url(self, raw_url: str) -> Dict[str, Any]:
        """Query VirusTotal URL reputation using URL-safe base64 identifier."""
        url_id = base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("utf-8").strip("=")
        return self._request(f"urls/{url_id}", raw_url, "URL")
