"""Risk scoring engine for IoC enrichment outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(slots=True)
class RiskConfig:
    """Configurable thresholds for SOC risk categorization."""

    medium_min: int = 1
    high_min: int = 6


@dataclass(slots=True)
class RiskResult:
    """Numeric and label representation of computed IoC risk."""

    score: int
    level: str


def _extract_score(vt_data: Dict[str, Any] | None, abuse_data: Dict[str, Any] | None) -> int:
    """Build a single score from VirusTotal and AbuseIPDB reputation signals."""
    score = 0

    if vt_data and vt_data.get("status") == "ok":
        score += int(vt_data.get("malicious", 0))
        score += int(vt_data.get("suspicious", 0))

    if abuse_data and abuse_data.get("status") == "ok":
        confidence = int(abuse_data.get("abuse_confidence_score", 0))
        # Convert 0-100 confidence into a coarse 0-10 additive score.
        score += round(confidence / 10)

    return score


def score_ioc(
    vt_data: Dict[str, Any] | None,
    abuse_data: Dict[str, Any] | None,
    config: RiskConfig | None = None,
) -> RiskResult:
    """Assign Low/Medium/High risk based on aggregated threat intelligence score."""
    cfg = config or RiskConfig()
    score = _extract_score(vt_data, abuse_data)

    if score >= cfg.high_min:
        level = "HIGH"
    elif score >= cfg.medium_min:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskResult(score=score, level=level)
