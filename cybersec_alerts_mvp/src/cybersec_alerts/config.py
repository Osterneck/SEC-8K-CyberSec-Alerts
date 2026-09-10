"""Application configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings for the alert pipeline.

    Attributes:
        sec_user_agent: User-Agent sent to SEC endpoints.
        db_path: SQLite database path.
        timeout_seconds: HTTP request timeout.
        enforcement_pages: SEC litigation-release pages to inspect.
        minimum_alert_score: Lowest score that produces an alert.
    """

    sec_user_agent: str
    db_path: Path
    timeout_seconds: float = 20.0
    enforcement_pages: int = 3
    minimum_alert_score: int = 20

    @classmethod
    def from_env(cls) -> "Settings":
        """Builds settings from environment variables.

        Returns:
            Settings populated from the current process environment.
        """
        return cls(
            sec_user_agent=os.getenv("SEC_USER_AGENT", "").strip(),
            db_path=Path(
                os.getenv("CYBERSEC_DB_PATH", "cybersec_alerts.db")
            ),
            timeout_seconds=float(
                os.getenv("CYBERSEC_TIMEOUT_SECONDS", "20")
            ),
            enforcement_pages=int(
                os.getenv("CYBERSEC_ENFORCEMENT_PAGES", "3")
            ),
            minimum_alert_score=int(
                os.getenv("CYBERSEC_MIN_SCORE", "20")
            ),
        )
