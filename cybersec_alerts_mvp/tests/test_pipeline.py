"""Tests for longitudinal filing-to-enforcement correlation."""

from datetime import datetime, timezone
from pathlib import Path

from cybersec_alerts.models import EnforcementAction, SecFiling
from cybersec_alerts.pipeline import AlertPipeline
from cybersec_alerts.sec_client import FeedEntry
from cybersec_alerts.store import Store


class _FakeSecClient:
    def __init__(self) -> None:
        self._returned = False

    def list_current_8k(self, limit: int = 40) -> list[FeedEntry]:
        del limit
        if self._returned:
            return []
        self._returned = True
        return [
            FeedEntry(
                company_name="Example Holdings, Inc.",
                cik="0000123456",
                form="8-K",
                filed_at=datetime.now(timezone.utc),
                filing_url="https://www.sec.gov/index.htm",
                accession="0000123456-26-000001",
            )
        ]

    def fetch_filing(self, entry: FeedEntry) -> SecFiling:
        return SecFiling(
            cik=entry.cik,
            company_name=entry.company_name,
            form=entry.form,
            accession=entry.accession,
            filed_at=entry.filed_at,
            filing_url=entry.filing_url,
            document_url="https://www.sec.gov/document.htm",
            text=(
                "Item 1.05 Material Cybersecurity Incidents. The company "
                "determined a cybersecurity incident involving unauthorized "
                "access and customer data was material."
            ),
            items=("1.05",),
        )


class _FakeEnforcementClient:
    def __init__(self) -> None:
        self.actions: list[EnforcementAction] = []

    def fetch_recent(self, pages: int = 3) -> list[EnforcementAction]:
        del pages
        return self.actions

    def correlate(
        self,
        company_name: str,
        actions: list[EnforcementAction],
    ) -> tuple[EnforcementAction, ...]:
        if "Example Holdings" not in company_name:
            return ()
        return tuple(
            action
            for action in actions
            if "Example Holdings" in action.title
        )


def test_subsequent_enforcement_generates_follow_up(tmp_path: Path) -> None:
    sec_client = _FakeSecClient()
    enforcement_client = _FakeEnforcementClient()
    store = Store(tmp_path / "pipeline.db")
    pipeline = AlertPipeline(
        sec_client=sec_client,  # type: ignore[arg-type]
        enforcement_client=enforcement_client,  # type: ignore[arg-type]
        store=store,
    )

    first = pipeline.run_once()
    assert len(first) == 1
    assert "CYBERSEC SEC ALERT" in first[0]

    enforcement_client.actions = [
        EnforcementAction(
            title="Example Holdings, Inc.",
            url="https://www.sec.gov/enforcement/example",
            release_number="LR-99999",
        )
    ]
    second = pipeline.run_once()
    assert len(second) == 1
    assert "SEC ENFORCEMENT FOLLOW-UP" in second[0]

    third = pipeline.run_once()
    assert third == []
