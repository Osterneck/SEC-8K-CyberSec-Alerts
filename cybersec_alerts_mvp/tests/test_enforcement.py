"""Tests for enforcement entity correlation."""

from cybersec_alerts.enforcement import SecEnforcementClient
from cybersec_alerts.models import EnforcementAction


def test_company_name_match() -> None:
    client = SecEnforcementClient("TestAgent test@example.com")
    actions = [
        EnforcementAction(
            title="Example Holdings, Inc. and John Doe",
            url="https://www.sec.gov/example",
            release_number="LR-12345",
        ),
        EnforcementAction(
            title="Other Registrant LLC",
            url="https://www.sec.gov/other",
            release_number="LR-12346",
        ),
    ]
    matches = client.correlate("Example Holdings, Inc.", actions)
    assert len(matches) == 1
    assert matches[0].release_number == "LR-12345"


def test_release_number_parsing_from_civil_and_admin_urls() -> None:
    from cybersec_alerts.enforcement import _release_number

    assert _release_number(
        "https://www.sec.gov/enforcement-litigation/"
        "litigation-releases/lr-26632"
    ) == "LR-26632"
    assert _release_number(
        "https://www.sec.gov/files/litigation/admin/2026/34-106285.pdf"
    ) == "34-106285"
