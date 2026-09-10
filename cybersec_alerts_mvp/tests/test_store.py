"""Tests for SQLite persistence."""

from pathlib import Path

from cybersec_alerts.demo import build_demo_alerts
from cybersec_alerts.store import Store


def test_store_round_trip(tmp_path: Path) -> None:
    store = Store(tmp_path / "test.db")
    alert = build_demo_alerts()[0]
    store.save_filing(alert.incident.filing)
    store.save_incident(alert.incident)
    store.save_alert(alert)
    assert store.seen(alert.incident.filing.accession)
    rows = store.recent_alerts()
    assert len(rows) == 1
    assert rows[0]["company_name"] == "Example Holdings, Inc."
