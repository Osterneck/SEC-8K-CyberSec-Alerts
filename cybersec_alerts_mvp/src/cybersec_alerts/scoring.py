"""Deterministic legal, regulatory, and underwriting risk scoring."""

from __future__ import annotations

from cybersec_alerts.models import (
    CyberIncident,
    DisclosureType,
    MaterialityState,
    Urgency,
)


class ExposureScorer:
    """Scores cyber incidents using explainable legal-risk rules."""

    def score(self, incident: CyberIncident) -> CyberIncident:
        """Adds risk score, urgency, exposures, and recommended actions.

        Args:
            incident: Classified cyber incident.

        Returns:
            The same incident object with scoring fields populated.
        """
        score = 55 if (
            incident.disclosure_type == DisclosureType.ITEM_1_05
        ) else 25
        signal_points = {
            "unauthorized_access": 5,
            "ransomware_or_encryption": 10,
            "data_exfiltration": 15,
            "personal_or_customer_data": 10,
            "operational_disruption": 10,
            "third_party": 5,
            "law_enforcement": 3,
            "financial_impact": 10,
            "possible_item_mismatch": 15,
        }
        score += sum(
            signal_points.get(signal, 0) for signal in incident.signals
        )

        if incident.materiality == MaterialityState.NOT_MATERIAL:
            score -= 8
        elif incident.materiality == MaterialityState.UNDETERMINED:
            score += 3

        incident.risk_score = max(0, min(score, 100))
        incident.urgency = _urgency(incident.risk_score)
        incident.exposures = _exposures(incident)
        incident.recommended_actions = _recommended_actions(incident)
        return incident


def _urgency(score: int) -> Urgency:
    if score >= 80:
        return Urgency.CRITICAL
    if score >= 60:
        return Urgency.HIGH
    if score >= 40:
        return Urgency.MODERATE
    return Urgency.WATCH


def _exposures(incident: CyberIncident) -> tuple[str, ...]:
    exposures: list[str] = ["SEC disclosure and materiality process"]
    signals = set(incident.signals)

    if incident.disclosure_type == DisclosureType.ITEM_1_05:
        exposures.append("securities litigation / disclosure scrutiny")
    if "possible_item_mismatch" in signals:
        exposures.append("Form 8-K item-selection / disclosure consistency")
    if "personal_or_customer_data" in signals:
        exposures.append("privacy notification and regulatory exposure")
    if "operational_disruption" in signals:
        exposures.append("business interruption / cyber coverage exposure")
    if "third_party" in signals:
        exposures.append("third-party and vendor-management exposure")
    if "data_exfiltration" in signals:
        exposures.append("data-loss, extortion, and claims severity")
    exposures.append("cyber insurance underwriting change signal")
    return tuple(dict.fromkeys(exposures))


def _recommended_actions(incident: CyberIncident) -> tuple[str, ...]:
    actions = [
        "Review the filing against prior cyber disclosures and Item 1C risk "
        "language.",
        "Track amendments, quantified impacts, regulator notices, and new "
        "litigation.",
    ]
    if incident.disclosure_type == DisclosureType.ITEM_1_05:
        actions.append(
            "Identify the materiality-determination date and review the "
            "four-business-day Item 1.05 filing timeline."
        )
    if incident.disclosure_type == DisclosureType.ITEM_8_01:
        actions.append(
            "Watch for a later Item 1.05 filing if the registrant subsequently "
            "determines the incident is material, including the resulting "
            "four-business-day filing timeline."
        )
    if "possible_item_mismatch" in incident.signals:
        actions.append(
            "Review whether Item 1.05 was required after the stated "
            "materiality determination and whether a timely Item 1.05 "
            "filing followed."
        )
    if "third_party" in incident.signals:
        actions.append(
            "Identify the vendor/service provider and map portfolio or insured "
            "concentration exposure."
        )
    if "personal_or_customer_data" in incident.signals:
        actions.append(
            "Assess affected-person scope, state notice triggers, contractual "
            "notice duties, and privacy regulator exposure."
        )
    if "operational_disruption" in incident.signals:
        actions.append(
            "Reassess business-interruption severity, recovery timeline, and "
            "dependent-business exposure."
        )
    return tuple(actions)
