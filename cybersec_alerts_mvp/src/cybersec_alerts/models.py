"""Domain models used throughout the application."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum


class DisclosureType(StrEnum):
    """Supported SEC cybersecurity disclosure types."""

    ITEM_1_05 = "item_1_05_material_cyber"
    ITEM_8_01 = "item_8_01_other_cyber"


class MaterialityState(StrEnum):
    """Registrant materiality state inferred from the filing."""

    MATERIAL = "material"
    NOT_MATERIAL = "not_material"
    UNDETERMINED = "undetermined"


class Urgency(StrEnum):
    """Human-facing urgency level."""

    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    WATCH = "watch"


@dataclass(slots=True)
class SecFiling:
    """Normalized SEC filing.

    Attributes:
        cik: SEC Central Index Key when available.
        company_name: Registrant name.
        form: SEC form type.
        accession: Filing accession number when available.
        filed_at: Filing timestamp.
        filing_url: SEC filing-index URL.
        document_url: Primary filing-document URL.
        text: Normalized plain-text filing body.
        items: Detected Form 8-K item numbers.
    """

    cik: str
    company_name: str
    form: str
    accession: str
    filed_at: datetime
    filing_url: str
    document_url: str
    text: str
    items: tuple[str, ...] = ()


@dataclass(slots=True)
class CyberIncident:
    """Cybersecurity incident extracted from an SEC filing."""

    filing: SecFiling
    disclosure_type: DisclosureType
    materiality: MaterialityState
    signals: tuple[str, ...]
    summary: str
    risk_score: int = 0
    urgency: Urgency = Urgency.WATCH
    exposures: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()


@dataclass(slots=True)
class EnforcementAction:
    """SEC enforcement action used for correlation."""

    title: str
    url: str
    release_number: str
    source_type: str = "litigation_release"
    published_at: datetime | None = None
    text: str = ""


@dataclass(slots=True)
class Alert:
    """Rendered alert and its structured metadata."""

    incident: CyberIncident
    enforcement_matches: tuple[EnforcementAction, ...] = ()
    rendered_text: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
