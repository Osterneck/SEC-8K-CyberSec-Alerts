"""FastAPI web layer for CyberSec Alerts.

Drop this file into src/cybersec_alerts/api.py
Run with: uvicorn cybersec_alerts.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from cybersec_alerts.config import Settings
from cybersec_alerts.demo import build_demo_alerts
from cybersec_alerts.enforcement import SecEnforcementClient
from cybersec_alerts.pipeline import AlertPipeline
from cybersec_alerts.sec_client import SecClient
from cybersec_alerts.store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App state (created once at startup)
# ---------------------------------------------------------------------------

_settings: Settings | None = None
_store: Store | None = None
_pipeline: AlertPipeline | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _settings, _store, _pipeline
    _settings = Settings.from_env()
    _store = Store(_settings.db_path)
    if _settings.sec_user_agent:
        sec_client = SecClient(
            user_agent=_settings.sec_user_agent,
            timeout_seconds=_settings.timeout_seconds,
        )
        enforcement_client = SecEnforcementClient(
            user_agent=_settings.sec_user_agent,
            timeout_seconds=_settings.timeout_seconds,
        )
        _pipeline = AlertPipeline(
            sec_client=sec_client,
            enforcement_client=enforcement_client,
            store=_store,
            minimum_alert_score=_settings.minimum_alert_score,
        )
    else:
        LOGGER.warning("SEC_USER_AGENT not set — live scan disabled.")
    yield


app = FastAPI(
    title="SEC CyberSec Alerts",
    description="Actionable SEC 8-K cybersecurity filing alerts for legal and risk teams.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe for Render / Cloudflare tunnel."""
    return {"status": "ok"}


@app.get("/api/demo")
def demo() -> dict[str, Any]:
    """Returns two synthetic alerts — no SEC network call, always available."""
    alerts = build_demo_alerts()
    return {
        "source": "demo",
        "count": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


@app.get("/api/history")
def history(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    """Returns persisted alert history from SQLite."""
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    rows = _store.recent_alerts(limit=limit)
    return {
        "count": len(rows),
        "alerts": [dict(r) for r in rows],
    }


@app.get("/api/scan")
def scan(
    limit: int = Query(default=40, ge=1, le=200),
    enforcement_pages: int = Query(default=3, ge=1, le=10),
) -> dict[str, Any]:
    """Runs one live SEC filing scan cycle. Requires SEC_USER_AGENT env var."""
    if _pipeline is None:
        raise HTTPException(
            status_code=503,
            detail="SEC_USER_AGENT not configured — live scan unavailable.",
        )
    alerts = _pipeline.run_once_structured(
        limit=limit,
        enforcement_pages=enforcement_pages,
    )
    return {
        "source": "live",
        "new_alerts": len(alerts),
        "alerts": [_alert_to_dict(a) for a in alerts],
    }


# ---------------------------------------------------------------------------
# Static frontend (served from /static, built separately)
# ---------------------------------------------------------------------------

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alert_to_dict(alert: Any) -> dict[str, Any]:
    inc = alert.incident
    filing = inc.filing
    return {
        "urgency": inc.urgency.value,
        "risk_score": inc.risk_score,
        "company_name": filing.company_name,
        "accession": filing.accession,
        "disclosure_type": inc.disclosure_type.value,
        "materiality": inc.materiality.value,
        "summary": inc.summary,
        "filing_url": filing.document_url,
        "signals": list(inc.signals),
        "exposures": list(inc.exposures),
        "recommended_actions": list(inc.recommended_actions),
        "enforcement_matches": [
            {"title": e.title, "url": e.url, "release_number": e.release_number}
            for e in alert.enforcement_matches
        ],
        "rendered_text": alert.rendered_text,
        "created_at": alert.created_at.isoformat(),
    }
