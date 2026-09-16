"""SQLite persistence for filings, incidents, enforcement, and alerts."""

from __future__ import annotations

from contextlib import closing
from typing import Any
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from cybersec_alerts.models import (
    Alert,
    CyberIncident,
    EnforcementAction,
    SecFiling,
)


class Store:
    """SQLite repository for pipeline state and alert history."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS filings (
                    accession TEXT PRIMARY KEY,
                    cik TEXT NOT NULL,
                    company_name TEXT NOT NULL,
                    form TEXT NOT NULL,
                    filed_at TEXT NOT NULL,
                    filing_url TEXT NOT NULL,
                    document_url TEXT NOT NULL,
                    items_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    accession TEXT PRIMARY KEY,
                    disclosure_type TEXT NOT NULL,
                    materiality TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    urgency TEXT NOT NULL,
                    exposures_json TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    FOREIGN KEY(accession) REFERENCES filings(accession)
                );

                CREATE TABLE IF NOT EXISTS enforcement_actions (
                    url TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    release_number TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS enforcement_links (
                    enforcement_url TEXT NOT NULL,
                    accession TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(enforcement_url, accession),
                    FOREIGN KEY(accession) REFERENCES filings(accession)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    accession TEXT NOT NULL,
                    alert_type TEXT NOT NULL DEFAULT 'filing',
                    rendered_text TEXT NOT NULL,
                    enforcement_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(accession) REFERENCES filings(accession)
                );
                """
            )
            _ensure_alert_type_column(connection)
            connection.commit()

    def seen(self, accession: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM filings WHERE accession = ? LIMIT 1",
                (accession,),
            ).fetchone()
        return row is not None

    def save_filing(self, filing: SecFiling) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO filings (
                    accession, cik, company_name, form, filed_at,
                    filing_url, document_url, items_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    filing.accession,
                    filing.cik,
                    filing.company_name,
                    filing.form,
                    filing.filed_at.isoformat(),
                    filing.filing_url,
                    filing.document_url,
                    json.dumps(filing.items),
                    _utc_now(),
                ),
            )
            connection.commit()

    def save_incident(self, incident: CyberIncident) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    accession, disclosure_type, materiality, signals_json,
                    summary, risk_score, urgency, exposures_json, actions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.filing.accession,
                    incident.disclosure_type.value,
                    incident.materiality.value,
                    json.dumps(incident.signals),
                    incident.summary,
                    incident.risk_score,
                    incident.urgency.value,
                    json.dumps(incident.exposures),
                    json.dumps(incident.recommended_actions),
                ),
            )
            connection.commit()

    def save_alert(self, alert: Alert) -> None:
        enforcement = [
            {
                "title": action.title,
                "url": action.url,
                "release_number": action.release_number,
                "source_type": action.source_type,
            }
            for action in alert.enforcement_matches
        ]
        self.save_rendered_alert(
            accession=alert.incident.filing.accession,
            alert_type="filing",
            rendered_text=alert.rendered_text,
            enforcement=enforcement,
            created_at=alert.created_at.isoformat(),
        )

    def save_rendered_alert(
        self,
        accession: str,
        alert_type: str,
        rendered_text: str,
        enforcement: list[dict[str, str]],
        created_at: str | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    accession, alert_type, rendered_text,
                    enforcement_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    accession,
                    alert_type,
                    rendered_text,
                    json.dumps(enforcement),
                    created_at or _utc_now(),
                ),
            )
            connection.commit()

    def tracked_incidents(self) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT
                    f.accession,
                    f.cik,
                    f.company_name,
                    f.document_url,
                    f.filed_at,
                    i.disclosure_type,
                    i.risk_score
                FROM filings AS f
                JOIN incidents AS i ON i.accession = f.accession
                ORDER BY f.filed_at DESC
                """
            ).fetchall()
        return list(rows)

    def save_enforcement_action(self, action: EnforcementAction) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO enforcement_actions (
                    url, title, release_number, source_type, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    action.url,
                    action.title,
                    action.release_number,
                    action.source_type,
                    _utc_now(),
                ),
            )
            connection.commit()

    def enforcement_link_exists(self, action_url: str, accession: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT 1 FROM enforcement_links
                WHERE enforcement_url = ? AND accession = ?
                LIMIT 1
                """,
                (action_url, accession),
            ).fetchone()
        return row is not None

    def save_enforcement_link(self, action_url: str, accession: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO enforcement_links (
                    enforcement_url, accession, created_at
                ) VALUES (?, ?, ?)
                """,
                (action_url, accession, _utc_now()),
            )
            connection.commit()

    def recent_alerts(self, limit: int = 20, item_filter: str = "all") -> list[sqlite3.Row]:
        """Returns recent alert rows fully joined to filing and incident data.

        Args:
            limit: Maximum rows to return.
            item_filter: "all", "1.05", or "8.01" to filter by disclosure type.
        """
        filter_clause = ""
        params: list[Any] = []
        if item_filter == "1.05":
            filter_clause = "AND INSTR(i.disclosure_type, '1_05') > 0"
        elif item_filter == "8.01":
            filter_clause = "AND INSTR(i.disclosure_type, '8_01') > 0"
        params.append(max(1, limit))

        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                SELECT
                    a.id,
                    a.accession,
                    a.alert_type,
                    a.rendered_text,
                    a.enforcement_json,
                    a.created_at,
                    f.company_name,
                    f.filing_url,
                    f.document_url,
                    f.filed_at,
                    i.disclosure_type,
                    i.materiality,
                    i.risk_score,
                    i.urgency,
                    i.summary,
                    i.exposures_json,
                    i.signals_json
                FROM alerts AS a
                JOIN filings AS f ON f.accession = a.accession
                LEFT JOIN incidents AS i ON i.accession = a.accession
                WHERE 1=1 {filter_clause}
                ORDER BY f.filed_at DESC, a.id DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
        return list(rows)


def _ensure_alert_type_column(connection: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "alert_type" not in columns:
        connection.execute(
            "ALTER TABLE alerts ADD COLUMN alert_type TEXT NOT NULL "
            "DEFAULT 'filing'"
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
