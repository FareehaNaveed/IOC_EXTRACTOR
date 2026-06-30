# SOC IoC Extractor and Threat Intelligence Enrichment

Production-style Python 3.13 project for extracting IoCs from SOC alerts, enriching with VirusTotal and AbuseIPDB, scoring risk, and generating JSON and CSV reports.

## Features
- Regex extraction for IPv4, URLs, domains, MD5, SHA1, SHA256
- IoC de-duplication and structured output
- VirusTotal enrichment for IP, domain, URL, and file hashes
- AbuseIPDB enrichment for IP reputation
- Configurable risk scoring engine (Low, Medium, High)
- JSON and CSV report generation in reports folder
- Application logging to logs/application.log
- Automatic processing of both sample files

## Folder Structure

- main.py: Application entry point and SOC processing workflow
- config.py: Central settings, paths, API keys, and timeout
- regex_extractor.py: Reusable regex extraction logic
- virustotal.py: VirusTotal API client module
- abuseipdb.py: AbuseIPDB API client module
- risk_scoring.py: Risk calculation and thresholds
- report_generator.py: JSON and CSV report generation
- logger.py: Logging setup for console and file
- utils.py: Helper methods and color formatting
- benign_alert.txt: Benign SOC sample alert
- malicious_alert.txt: Malicious SOC sample alert
- reports/report.json: Output JSON report
- reports/report.csv: Output CSV report
- logs/application.log: Runtime logs

## Installation

1. Ensure Python 3.13 is installed.
2. Open this project in Visual Studio Code.
3. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Configure API Keys

Edit config.py and set:
- VT_API_KEY
- ABUSEIPDB_API_KEY

Example:

```python
VT_API_KEY = "<your_virustotal_api_key>"
ABUSEIPDB_API_KEY = "<your_abuseipdb_api_key>"
```

## Run

```powershell
python main.py
```

## Expected Terminal Output

```text
====================================
IOC EXTRACTION REPORT
====================================
Processing: malicious_alert.txt
✓ IP Found
✓ URL Found
✓ Domain Found
✓ SHA256 Found
Checking VirusTotal...
Checking AbuseIPDB...
Risk Score: HIGH
JSON Report Generated: reports/report.json
CSV Report Generated: reports/report.csv
Completed Successfully
====================================
```

## Output Fields
Each report row contains:
- alert_id
- ioc
- ioc_type
- source_file
- virustotal_reputation
- abuseipdb_reputation
- risk_score
- risk_numeric_score
- timestamp

## Error Handling Coverage
- Missing or empty alert files
- No internet / network failures
- DNS and transport errors
- API timeout handling
- Invalid API key handling
- Rate limits (HTTP 429)
- Missing reports/logs directories (auto-created)

## Screenshot Placeholders
- docs/screenshots/run-output.png
- docs/screenshots/report-preview.png

## Future Improvements
- Async API enrichment for higher throughput
- Caching layer for IoC lookups
- Unit tests and CI pipeline
- STIX/TAXII export support
- CLI arguments for custom alert input paths
