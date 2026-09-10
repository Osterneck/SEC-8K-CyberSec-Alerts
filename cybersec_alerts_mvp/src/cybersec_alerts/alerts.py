"""Plain-English alert rendering."""

from __future__ import annotations

from cybersec_alerts.models import Alert, DisclosureType, MaterialityState


class AlertRenderer:
    """Renders concise, actionable alerts for professional users."""

    def render(self, alert: Alert) -> str:
        """Renders an alert as plain text.

        Args:
            alert: Structured alert.

        Returns:
            Human-readable alert body.
        """
        incident = alert.incident
        filing = incident.filing
        item_label = (
            "Item 1.05 — Material Cybersecurity Incident"
            if incident.disclosure_type == DisclosureType.ITEM_1_05
            else "Item 8.01 — Cybersecurity / Other Event"
        )
        lines = [
            (
                f"[{incident.urgency.value.upper()}] CYBERSEC SEC ALERT — "
                f"{filing.company_name}"
            ),
            "",
            f"FILING: {item_label}",
            f"RISK SCORE: {incident.risk_score}/100",
            f"MATERIALITY: {_materiality_text(incident.materiality)}",
            "",
            "WHAT HAPPENED",
            incident.summary,
            "",
            "WHY IT MATTERS",
            _why_it_matters(alert),
            "",
            "EXPOSURE SIGNALS",
            *[f"- {value}" for value in incident.exposures],
            "",
            "ACTION NOW",
            *[f"- {value}" for value in incident.recommended_actions],
            "",
            "SEC ENFORCEMENT HISTORY SIGNAL",
            _enforcement_text(alert),
            "",
            f"SOURCE: {filing.document_url or filing.filing_url}",
        ]
        return "\n".join(lines)


def _materiality_text(state: MaterialityState) -> str:
    if state == MaterialityState.MATERIAL:
        return "Registrant has determined the incident is material."
    if state == MaterialityState.NOT_MATERIAL:
        return "Registrant language indicates no material impact."
    return "Materiality is not yet determined or remains unresolved."


def _why_it_matters(alert: Alert) -> str:
    incident = alert.incident
    if incident.disclosure_type == DisclosureType.ITEM_1_05:
        return (
            "The registrant has crossed the SEC's Item 1.05 materiality "
            "threshold. Review disclosure timing, evolving impact, prior risk "
            "statements, insurance implications, and follow-on litigation."
        )
    if incident.materiality == MaterialityState.MATERIAL:
        return (
            "The filing uses Item 8.01 while its text appears to state a "
            "materiality determination. Treat this as a disclosure-consistency "
            "review signal and check for a corresponding Item 1.05 filing."
        )
    return (
        "This is a cyber-related Item 8.01 disclosure rather than an Item "
        "1.05 material-incident filing. Treat it as an early-warning signal "
        "and watch for a later materiality determination or Item 1.05 filing."
    )


def _enforcement_text(alert: Alert) -> str:
    if not alert.enforcement_matches:
        return (
            "No recent same-entity SEC civil or administrative action "
            "matched by the MVP entity resolver. This is not a finding of "
            "no enforcement history."
        )
    parts = []
    for action in alert.enforcement_matches[:3]:
        identifier = action.release_number or "SEC release"
        parts.append(f"{identifier}: {action.title} ({action.url})")
    return " | ".join(parts)
