"""Tests for deterministic exposure scoring."""

from datetime import datetime, timezone

from cybersec_alerts.models import (
    CyberIncident,
    DisclosureType,
    MaterialityState,
    SecFiling,
    Urgency,
)
from cybersec_alerts.scoring import ExposureScorer


def _incident() -> CyberIncident:
    filing = SecFiling(
        cik="0000123456",
        company_name="Example Corp.",
        form="8-K",
        accession="0000123456-26-000001",
        filed_at=datetime.now(timezone.utc),
        filing_url="https://www.sec.gov/index.htm",
        document_url="https://www.sec.gov/doc.htm",
        text="",
        items=("1.05",),
    )
    return CyberIncident(
        filing=filing,
        disclosure_type=DisclosureType.ITEM_1_05,
        materiality=MaterialityState.MATERIAL,
        signals=(
            "data_exfiltration",
            "personal_or_customer_data",
            "operational_disruption",
        ),
        summary="Example.",
    )


def test_high_severity_105_scores_high() -> None:
    incident = ExposureScorer().score(_incident())
    assert incident.risk_score >= 80
    assert incident.urgency == Urgency.CRITICAL
    assert any("privacy" in value for value in incident.exposures)


def test_actions_include_follow_on_monitoring() -> None:
    incident = ExposureScorer().score(_incident())
    assert any("amendments" in value for value in incident.recommended_actions)
