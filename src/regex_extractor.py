"""Regex-based IoC extraction utilities."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List


IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
URL_PATTERN = re.compile(r"\bhttps?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[A-Za-z]{2,63}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
ALERT_ID_PATTERN = re.compile(r"Alert\s*ID\s*:\s*(\S+)", re.IGNORECASE)


@dataclass(slots=True)
class ExtractedIoCs:
    """Structured collection of extracted indicators of compromise."""

    alert_id: str | None
    ipv4: List[str]
    urls: List[str]
    domains: List[str]
    md5: List[str]
    sha1: List[str]
    sha256: List[str]

    def to_dict(self) -> Dict[str, List[str] | str | None]:
        """Convert extracted IoCs to a serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "ipv4": self.ipv4,
            "urls": self.urls,
            "domains": self.domains,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }


def _unique_sorted(matches: List[str]) -> List[str]:
    """Normalize, de-duplicate, and sort regex matches for deterministic output."""
    return sorted({match.strip().strip(",.;") for match in matches if match and match.strip()})


def extract_iocs_from_text(text: str) -> ExtractedIoCs:
    """Extract all supported IoCs from raw alert text using reusable regex patterns."""
    alert_match = ALERT_ID_PATTERN.search(text)
    alert_id = alert_match.group(1) if alert_match else None

    ipv4 = _unique_sorted(IPV4_PATTERN.findall(text))
    urls = _unique_sorted(URL_PATTERN.findall(text))
    md5 = _unique_sorted(MD5_PATTERN.findall(text))
    sha1 = _unique_sorted(SHA1_PATTERN.findall(text))
    sha256 = _unique_sorted(SHA256_PATTERN.findall(text))

    raw_domains = _unique_sorted(DOMAIN_PATTERN.findall(text))

    # Avoid duplicate domain reporting when already represented inside URLs.
    url_domains = {
        re.sub(r"^www\.", "", re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower())
        for url in urls
    }
    domains = [domain for domain in raw_domains if domain.lower() not in url_domains]

    return ExtractedIoCs(
        alert_id=alert_id,
        ipv4=ipv4,
        urls=urls,
        domains=domains,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )
