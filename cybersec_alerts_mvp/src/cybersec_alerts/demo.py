"""Offline demonstration data."""

from __future__ import annotations

from datetime import datetime, timezone

from cybersec_alerts.alerts import AlertRenderer
from cybersec_alerts.classifier import CyberFilingClassifier
from cybersec_alerts.models import Alert, SecFiling
from cybersec_alerts.scoring import ExposureScorer


DEMO_105_TEXT = """
Item 1.05 Material Cybersecurity Incidents.
Example Holdings, Inc. determined that a cybersecurity incident involving
unauthorized access to portions of its network is material. The threat actor
exfiltrated files containing customer personal information. The incident
caused operational disruption, and the company is evaluating the impact on
its financial condition and results of operations. The company notified law
enforcement and engaged external cybersecurity specialists.
"""

DEMO_801_TEXT = """
Item 8.01 Other Events.
Example Services Corp. detected unauthorized access involving a third-party
service provider. The investigation remains ongoing, and the company has not
yet determined whether the incident is material. The company has contained
the affected environment and is assessing whether customer data was acquired.
"""


def build_demo_alerts() -> list[Alert]:
    """Builds two synthetic alerts without network access."""
    classifier = CyberFilingClassifier()
    scorer = ExposureScorer()
    renderer = AlertRenderer()
    samples = [
        _filing(
            company="Example Holdings, Inc.",
            accession="0000000000-26-000001",
            text=DEMO_105_TEXT,
            items=("1.05",),
        ),
        _filing(
            company="Example Services Corp.",
            accession="0000000000-26-000002",
            text=DEMO_801_TEXT,
            items=("8.01",),
        ),
    ]
    alerts: list[Alert] = []
    for filing in samples:
        incident = classifier.classify(filing)
        if incident is None:
            continue
        scorer.score(incident)
        alert = Alert(incident=incident)
        alert.rendered_text = renderer.render(alert)
        alerts.append(alert)
    return alerts


def _filing(
    company: str,
    accession: str,
    text: str,
    items: tuple[str, ...],
) -> SecFiling:
    return SecFiling(
        cik="0000000000",
        company_name=company,
        form="8-K",
        accession=accession,
        filed_at=datetime.now(timezone.utc),
        filing_url="https://www.sec.gov/example-index.htm",
        document_url="https://www.sec.gov/example.htm",
        text=text,
        items=items,
    )
