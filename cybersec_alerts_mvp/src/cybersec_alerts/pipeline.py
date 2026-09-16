"""Alert pipeline orchestration."""

from __future__ import annotations

from collections.abc import Iterable
import logging

from cybersec_alerts.alerts import AlertRenderer
from cybersec_alerts.classifier import CyberFilingClassifier
from cybersec_alerts.enforcement import SecEnforcementClient
from cybersec_alerts.models import Alert, EnforcementAction
from cybersec_alerts.scoring import ExposureScorer
from cybersec_alerts.sec_client import SecClient
from cybersec_alerts.store import Store


LOGGER = logging.getLogger(__name__)


class AlertPipeline:
    """Coordinates ingestion, classification, scoring, and correlation."""

    def __init__(
        self,
        sec_client: SecClient,
        enforcement_client: SecEnforcementClient,
        store: Store,
        minimum_alert_score: int = 20,
    ) -> None:
        self._sec_client = sec_client
        self._enforcement_client = enforcement_client
        self._store = store
        self._minimum_alert_score = minimum_alert_score
        self._classifier = CyberFilingClassifier()
        self._scorer = ExposureScorer()
        self._renderer = AlertRenderer()

    def run_once(
        self,
        limit: int = 40,
        enforcement_pages: int = 3,
    ) -> list[str]:
        """Runs one full filing and enforcement correlation cycle.

        Returns:
            Newly generated rendered alert bodies (strings) — for CLI use.
        """
        alerts = self.run_once_structured(limit=limit, enforcement_pages=enforcement_pages)
        return [a.rendered_text for a in alerts]

    def run_once_structured(
        self,
        limit: int = 40,
        enforcement_pages: int = 3,
    ) -> list[Alert]:
        """Runs one full filing and enforcement correlation cycle.

        Returns:
            Newly generated Alert objects — for API/web use.
        """
        actions = self._safe_enforcement_fetch(enforcement_pages)
        self._process_enforcement_updates(actions)
        entries = self._sec_client.list_current_8k(limit=limit)

        alerts: list[Alert] = []
        for entry in entries:
            if entry.accession and self._store.seen(entry.accession):
                continue
            try:
                filing = self._sec_client.fetch_filing(entry)
            except Exception:  # pylint: disable=broad-exception-caught
                LOGGER.exception("Failed to fetch filing: %s", entry.filing_url)
                continue

            self._store.save_filing(filing)
            incident = self._classifier.classify(filing)
            if incident is None:
                continue
            self._scorer.score(incident)
            self._store.save_incident(incident)
            if incident.risk_score < self._minimum_alert_score:
                continue

            matches = self._enforcement_client.correlate(
                filing.company_name,
                actions,
            )
            alert = Alert(
                incident=incident,
                enforcement_matches=matches,
            )
            alert.rendered_text = self._renderer.render(alert)
            self._store.save_alert(alert)
            alerts.append(alert)
        return alerts

    def _process_enforcement_updates(
        self,
        actions: list[EnforcementAction],
    ) -> list[str]:
        rendered: list[str] = []
        tracked = self._store.tracked_incidents()
        for action in actions:
            self._store.save_enforcement_action(action)
            for row in tracked:
                matches = self._enforcement_client.correlate(
                    row["company_name"],
                    [action],
                )
                if not matches:
                    continue
                if self._store.enforcement_link_exists(
                    action.url,
                    row["accession"],
                ):
                    continue
                self._store.save_enforcement_link(
                    action.url,
                    row["accession"],
                )
                body = _render_enforcement_follow_up(
                    company_name=row["company_name"],
                    accession=row["accession"],
                    filing_url=row["document_url"],
                    action=action,
                )
                self._store.save_rendered_alert(
                    accession=row["accession"],
                    alert_type="enforcement_follow_up",
                    rendered_text=body,
                    enforcement=[
                        {
                            "title": action.title,
                            "url": action.url,
                            "release_number": action.release_number,
                            "source_type": action.source_type,
                        }
                    ],
                )
                rendered.append(body)
        return rendered

    def _safe_enforcement_fetch(
        self,
        pages: int,
    ) -> list[EnforcementAction]:
        try:
            return self._enforcement_client.fetch_recent(pages=pages)
        except Exception:  # pylint: disable=broad-exception-caught
            LOGGER.exception("SEC enforcement correlation source failed.")
            return []


def _render_enforcement_follow_up(
    company_name: str,
    accession: str,
    filing_url: str,
    action: EnforcementAction,
) -> str:
    source = action.source_type.replace("_", " ").title()
    release = action.release_number or "SEC action"
    lines = [
        f"[HIGH] SEC ENFORCEMENT FOLLOW-UP — {company_name}",
        "",
        f"TRIGGER: New matched {source} ({release})",
        f"ACTION: {action.title}",
        "",
        "WHAT CHANGED",
        (
            "The SEC enforcement monitor matched a newly observed action to "
            "an issuer already tracked for a cybersecurity disclosure."
        ),
        "",
        "WHY IT MATTERS",
        (
            "This is the downstream correlation the product is designed to "
            "surface. Compare the action with the original cyber disclosure, "
            "materiality analysis, controls language, and intervening filings."
        ),
        "",
        "ACTION NOW",
        (
            "- Review the SEC action for cyber, controls, disclosure, "
            "and scienter."
        ),
        (
            "- Compare allegations and dates against the original "
            "incident timeline."
        ),
        "- Reassess underwriting, litigation, and regulatory severity.",
        "- Check for parallel private litigation and other regulator activity.",
        "",
        f"ORIGINAL ACCESSION: {accession}",
        f"ORIGINAL FILING: {filing_url}",
        f"SEC ACTION: {action.url}",
    ]
    return "\n".join(lines)


def render_alerts(alerts: Iterable[Alert]) -> str:
    """Combines structured alerts for terminal output."""
    return "\n\n".join(alert.rendered_text for alert in alerts)
