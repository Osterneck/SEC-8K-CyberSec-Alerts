"""Tests for alert rendering."""

from cybersec_alerts.alerts import AlertRenderer
from cybersec_alerts.demo import build_demo_alerts


def test_demo_alert_has_actionable_sections() -> None:
    alert = build_demo_alerts()[0]
    rendered = AlertRenderer().render(alert)
    assert "WHAT HAPPENED" in rendered
    assert "WHY IT MATTERS" in rendered
    assert "ACTION NOW" in rendered
    assert "SEC ENFORCEMENT HISTORY SIGNAL" in rendered
