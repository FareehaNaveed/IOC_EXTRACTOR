"""Main entry point for SOC IoC extraction and enrichment pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import List

from abuseipdb import AbuseIPDBClient
from config import ALERT_FILES
from logger import get_logger
from regex_extractor import ExtractedIoCs, extract_iocs_from_text
from report_generator import generate_reports
from risk_scoring import score_ioc
from utils import (
    RED,
    RESET,
    GREEN,
    CYAN,
    YELLOW,
    bold,
    get_timestamp,
    read_text_file,
)
from virustotal import VirusTotalClient

LOGGER = get_logger(__name__)


def print_banner() -> None:
    """Print a colorful report banner for terminal execution."""
    print(f"{CYAN}{'=' * 36}{RESET}")
    print(f"{bold('IOC EXTRACTION REPORT')}")
    print(f"{CYAN}{'=' * 36}{RESET}")


def process_file(
    file_path: Path,
    vt_client: VirusTotalClient,
    abuse_client: AbuseIPDBClient,
) -> List[dict]:
    """Process one alert file and return report rows for all discovered IoCs."""
    LOGGER.info("Processing alert file: %s", file_path)
    print(f"\n{YELLOW}Processing:{RESET} {file_path.name}")

    text = read_text_file(file_path)
    extracted: ExtractedIoCs = extract_iocs_from_text(text)

    report_rows: List[dict] = []

    alert_id = extracted.alert_id or "UNKNOWN"

    if extracted.ipv4:
        print(f"{GREEN}✓ IP Found{RESET}")
    if extracted.urls:
        print(f"{GREEN}✓ URL Found{RESET}")
    if extracted.domains:
        print(f"{GREEN}✓ Domain Found{RESET}")
    if extracted.sha256:
        print(f"{GREEN}✓ SHA256 Found{RESET}")

    print(f"{CYAN}Checking VirusTotal...{RESET}")
    print(f"{CYAN}Checking AbuseIPDB...{RESET}")

    def build_row(ioc: str, ioc_type: str, vt_data: dict | None, abuse_data: dict | None) -> dict:
        risk = score_ioc(vt_data=vt_data, abuse_data=abuse_data)
        return {
            "alert_id": alert_id,
            "ioc": ioc,
            "ioc_type": ioc_type,
            "source_file": file_path.name,
            "virustotal_reputation": vt_data,
            "abuseipdb_reputation": abuse_data,
            "risk_score": risk.level,
            "risk_numeric_score": risk.score,
            "timestamp": get_timestamp(),
        }

    for ip in extracted.ipv4:
        vt_result = vt_client.lookup_ip(ip)
        abuse_result = abuse_client.lookup_ip(ip)
        report_rows.append(build_row(ip, "IPv4", vt_result, abuse_result))

    for url in extracted.urls:
        vt_result = vt_client.lookup_url(url)
        report_rows.append(build_row(url, "URL", vt_result, None))

    for domain in extracted.domains:
        vt_result = vt_client.lookup_domain(domain)
        report_rows.append(build_row(domain, "Domain", vt_result, None))

    for md5 in extracted.md5:
        vt_result = vt_client.lookup_hash(md5)
        report_rows.append(build_row(md5, "MD5", vt_result, None))

    for sha1 in extracted.sha1:
        vt_result = vt_client.lookup_hash(sha1)
        report_rows.append(build_row(sha1, "SHA1", vt_result, None))

    for sha256 in extracted.sha256:
        vt_result = vt_client.lookup_hash(sha256)
        report_rows.append(build_row(sha256, "SHA256", vt_result, None))

    highest_risk = "LOW"
    if any(r["risk_score"] == "HIGH" for r in report_rows):
        highest_risk = "HIGH"
    elif any(r["risk_score"] == "MEDIUM" for r in report_rows):
        highest_risk = "MEDIUM"

    risk_color = RED if highest_risk == "HIGH" else YELLOW if highest_risk == "MEDIUM" else GREEN
    print(f"{risk_color}Risk Score: {highest_risk}{RESET}")

    return report_rows


def main() -> None:
    """Execute the complete SOC IoC extraction pipeline for all configured alert files."""
    LOGGER.info("Application start")
    print_banner()

    vt_client = VirusTotalClient()
    abuse_client = AbuseIPDBClient()

    all_rows: List[dict] = []

    for alert_file in ALERT_FILES:
        all_rows.extend(process_file(alert_file, vt_client, abuse_client))

    json_path, csv_path = generate_reports(all_rows)

    print(f"{GREEN}JSON Report Generated:{RESET} {json_path}")
    print(f"{GREEN}CSV Report Generated:{RESET} {csv_path}")
    print(f"{GREEN}Completed Successfully{RESET}")
    print(f"{CYAN}{'=' * 36}{RESET}")

    LOGGER.info("Application completed successfully")


if __name__ == "__main__":
    main()
