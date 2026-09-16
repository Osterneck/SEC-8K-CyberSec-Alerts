"""FastAPI web layer for CyberSec Alerts."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from cybersec_alerts.config import Settings
from cybersec_alerts.enforcement import SecEnforcementClient
from cybersec_alerts.pipeline import AlertPipeline
from cybersec_alerts.sec_client import SecClient
from cybersec_alerts.store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger(__name__)

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
    description="Actionable SEC 8-K cybersecurity filing alerts.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Converts a sqlite3.Row to a fully populated alert dict."""
    d = dict(row)
    # Parse JSON fields
    for field in ("exposures_json", "signals_json", "enforcement_json"):
        if field in d and d[field]:
            key = field.replace("_json", "s") if field != "enforcement_json" else "enforcement"
            try:
                d[field.replace("_json", "")] = json.loads(d[field])
            except Exception:
                d[field.replace("_json", "")] = []
    d["exposures"] = d.pop("exposures_json", []) if "exposures_json" in d else d.get("exposures", [])
    d["signals"] = d.pop("signals_json", []) if "signals_json" in d else d.get("signals", [])
    return d


@app.get("/api/scan")
def scan(
    limit: int = Query(default=40, ge=1, le=200),
    enforcement_pages: int = Query(default=3, ge=1, le=10),
) -> dict[str, Any]:
    """Runs one live SEC filing scan, then returns most recent alerts from DB."""
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="SEC_USER_AGENT not configured.")
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")

    new_alerts = _pipeline.run_once_structured(
        limit=limit,
        enforcement_pages=enforcement_pages,
    )
    new_accessions = [a.incident.filing.accession for a in new_alerts]

    rows = _store.recent_alerts(limit=20)
    return {
        "source": "live",
        "new_alerts": len(new_alerts),
        "new_alert_accessions": new_accessions,
        "alerts": [_row_to_dict(r) for r in rows],
    }


@app.get("/api/history")
def history(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    """Returns persisted alert history from SQLite."""
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    rows = _store.recent_alerts(limit=limit)
    return {
        "count": len(rows),
        "alerts": [_row_to_dict(r) for r in rows],
    }


_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
