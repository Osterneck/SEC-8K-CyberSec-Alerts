
"""Explainable cybersecurity filing classifier."""

from __future__ import annotations

import re

from cybersec_alerts.models import (
    CyberIncident,
    DisclosureType,
    MaterialityState,
    SecFiling,
)
from cybersec_alerts.text_utils import sentence_candidates


_SIGNAL_PATTERNS: dict[str, tuple[str, ...]] = {
    "unauthorized_access": (
        "unauthorized access",
        "unauthorized occurrence",
        "unauthorized intrusion",
        "network intrusion",
    ),
    "ransomware_or_encryption": (
        "ransomware",
        "encrypted systems",
        "deployment of encryption",
    ),
    "data_exfiltration": (
        "exfiltrat",
        "acquired data",
        "stolen data",
        "downloaded data",
    ),
    "personal_or_customer_data": (
        "personal information",
        "personally identifiable",
        "customer data",
        "consumer data",
        "employee data",
    ),
    "operational_disruption": (
        "operational disruption",
        "business disruption",
        "systems offline",
        "shut down portions",
        "limitation of access",
        "disrupted operations",
    ),
    "third_party": (
        "third-party",
        "third party",
        "service provider",
        "vendor",
    ),
    "law_enforcement": (
        "law enforcement",
        "federal bureau of investigation",
        "fbi",
    ),
    "financial_impact": (
        "financial impact",
        "financial condition",
        "results of operations",
        "material costs",
        "material loss",
    ),
}

_CYBER_TERMS = (
    "cybersecurity incident",
    "cyber incident",
    "ransomware",
    "unauthorized access",
    "unauthorized occurrence",
    "data breach",
    "security incident",
    "network intrusion",
    "threat actor",
    "exfiltrat",
    "information security",
    "compromised systems",
)

# Boilerplate phrases to skip when building the summary
_BOILERPLATE_PATTERNS = (
    "emerging growth company",
    "indicate by check mark",
    "securities exchange act",
    "commission file number",
    "pursuant to section 13",
    "pursuant to rule",
    "incorporated in",
    "state of incorporation",
    "internal revenue",
    "registrant's telephone",
    "written communications",
    "soliciting material",
    "pre-commencement",
    "check the following",
    "shell company",
    "transition period",
    "fiscal year",
    "form 8-k",
    "current report",
    "date of report",
    "date of earliest",
)


class CyberFilingClassifier:
    """Classifies Form 8-K cybersecurity disclosures."""

    def classify(self, filing: SecFiling) -> CyberIncident | None:
        text_lower = filing.text.lower()
        has_105 = _contains_item(filing, "1.05")
        has_801 = _contains_item(filing, "8.01")

        if has_105:
            disclosure_type = DisclosureType.ITEM_1_05
            materiality = MaterialityState.MATERIAL
        elif has_801 and _is_cyber_text(text_lower):
            disclosure_type = DisclosureType.ITEM_8_01
            materiality = _infer_801_materiality(text_lower)
        else:
            return None

        signal_list = [
            key
            for key, patterns in _SIGNAL_PATTERNS.items()
            if any(pattern in text_lower for pattern in patterns)
        ]
        if (
            disclosure_type == DisclosureType.ITEM_8_01
            and materiality == MaterialityState.MATERIAL
        ):
            signal_list.append("possible_item_mismatch")
        signals = tuple(signal_list)
        return CyberIncident(
            filing=filing,
            disclosure_type=disclosure_type,
            materiality=materiality,
            signals=signals,
            summary=_summarize(filing.text, disclosure_type),
        )


def _contains_item(filing: SecFiling, item: str) -> bool:
    if item in filing.items:
        return True
    return bool(
        re.search(
            rf"\bItem\s+{re.escape(item)}\b",
            filing.text,
            flags=re.IGNORECASE,
        )
    )


def _is_cyber_text(text_lower: str) -> bool:
    matches = sum(term in text_lower for term in _CYBER_TERMS)
    return matches >= 1


def _infer_801_materiality(text_lower: str) -> MaterialityState:
    positive_patterns = (
        "determined that the incident is material",
        "determined the incident is material",
        "determined that the incident was material",
        "determined the incident was material",
    )
    negative_patterns = (
        "determined that the incident was not material",
        "determined the incident was not material",
        "incident is not material",
        "incident was not material",
        "determined to be immaterial",
        "not reasonably likely to have a material impact",
        "not reasonably likely to materially impact",
    )
    undetermined_patterns = (
        "has not yet determined",
        "not yet determined",
        "has not determined whether",
        "materiality determination remains",
        "investigation remains ongoing",
    )
    positive_match = re.search(
        r"determined(?: that)? (?:the )?(?:cybersecurity )?incident "
        r"(?:is|was) material",
        text_lower,
    )
    if positive_match or any(p in text_lower for p in positive_patterns):
        return MaterialityState.MATERIAL
    if any(p in text_lower for p in negative_patterns):
        return MaterialityState.NOT_MATERIAL
    if any(p in text_lower for p in undetermined_patterns):
        return MaterialityState.UNDETERMINED
    return MaterialityState.UNDETERMINED


def _is_boilerplate(sentence: str) -> bool:
    """Returns True if the sentence is cover-page or form boilerplate."""
    lower = sentence.lower()
    return any(pattern in lower for pattern in _BOILERPLATE_PATTERNS)


def _summarize(text: str, disclosure_type: DisclosureType) -> str:
    """Extracts 1-2 substantive cyber sentences, skipping boilerplate."""
    cyber_sentences: list[str] = []
    for sentence in sentence_candidates(text):
        lower = sentence.lower()
        if _is_boilerplate(sentence):
            continue
        if any(term in lower for term in _CYBER_TERMS):
            if len(sentence) > 420:
                sentence = f"{sentence[:417].rstrip()}..."
            cyber_sentences.append(sentence)
        if len(cyber_sentences) == 2:
            break

    if cyber_sentences:
        return " ".join(cyber_sentences)
    if disclosure_type == DisclosureType.ITEM_1_05:
        return "Registrant filed an Item 1.05 material cybersecurity incident disclosure."
    return "Registrant filed a cyber-related Item 8.01 disclosure."
