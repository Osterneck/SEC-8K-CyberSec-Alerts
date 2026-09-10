"""Tests for cybersecurity filing classification."""

from datetime import datetime, timezone

from cybersec_alerts.classifier import CyberFilingClassifier
from cybersec_alerts.models import (
    DisclosureType,
    MaterialityState,
    SecFiling,
)


def _filing(text: str, items: tuple[str, ...]) -> SecFiling:
    return SecFiling(
        cik="0000123456",
        company_name="Example Corp.",
        form="8-K",
        accession="0000123456-26-000001",
        filed_at=datetime.now(timezone.utc),
        filing_url="https://www.sec.gov/index.htm",
        document_url="https://www.sec.gov/doc.htm",
        text=text,
        items=items,
    )


def test_item_105_is_material_cyber() -> None:
    filing = _filing(
        "Item 1.05 Material Cybersecurity Incidents. A threat actor gained "
        "unauthorized access and exfiltrated customer data.",
        ("1.05",),
    )
    incident = CyberFilingClassifier().classify(filing)
    assert incident is not None
    assert incident.disclosure_type == DisclosureType.ITEM_1_05
    assert incident.materiality == MaterialityState.MATERIAL
    assert "data_exfiltration" in incident.signals


def test_cyber_item_801_is_in_scope() -> None:
    filing = _filing(
        "Item 8.01 Other Events. The company detected unauthorized access. "
        "The investigation remains ongoing and materiality is not yet "
        "determined.",
        ("8.01",),
    )
    incident = CyberFilingClassifier().classify(filing)
    assert incident is not None
    assert incident.disclosure_type == DisclosureType.ITEM_8_01
    assert incident.materiality == MaterialityState.UNDETERMINED


def test_non_cyber_item_801_is_ignored() -> None:
    filing = _filing(
        "Item 8.01 Other Events. The board declared a quarterly dividend.",
        ("8.01",),
    )
    assert CyberFilingClassifier().classify(filing) is None


def test_item_801_not_material_language_is_detected() -> None:
    filing = _filing(
        "Item 8.01 Other Events. A cybersecurity incident occurred. The "
        "company determined that the incident was not material.",
        ("8.01",),
    )
    incident = CyberFilingClassifier().classify(filing)
    assert incident is not None
    assert incident.materiality == MaterialityState.NOT_MATERIAL


def test_item_801_material_language_flags_item_review() -> None:
    filing = _filing(
        "Item 8.01 Other Events. The company determined that the "
        "cybersecurity incident is material after unauthorized access.",
        ("8.01",),
    )
    incident = CyberFilingClassifier().classify(filing)
    assert incident is not None
    assert incident.materiality == MaterialityState.MATERIAL
    assert "possible_item_mismatch" in incident.signals
