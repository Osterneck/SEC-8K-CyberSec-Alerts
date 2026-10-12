"""FastAPI web layer for CyberSec Alerts."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
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


# ---------------------------------------------------------------------------
# Widget feed — API-key gated JSON endpoint
# ---------------------------------------------------------------------------

@app.get("/api/widget-feed")
def widget_feed(
    key: str = Query(default=""),
    limit: int = Query(default=5, ge=1, le=20),
) -> dict[str, Any]:
    """Public widget feed — returns recent alerts. API key enforced in prod."""
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    # TODO: enforce key against DB of paid subscribers
    rows = _store.recent_alerts(limit=limit)
    return {
        "count": len(rows),
        "alerts": [_row_to_dict(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# Widget JS — embeddable script tag
# ---------------------------------------------------------------------------

_WIDGET_JS_TEMPLATE = """\
(function() {
  var KEY = '{{KEY}}';
  var FEED = 'https://form8.live/api/widget-feed?key=' + encodeURIComponent(KEY || 'demo') + '&limit=5';
  var STYLES = [
    '#f8w { font-family: Georgia, serif; background: #0f1117; border: 1px solid #2d3748; border-radius: 8px; padding: 1rem 1.25rem; max-width: 480px; color: #e2e8f0; }',
    '#f8w h4 { font-size: 0.8rem; font-weight: 600; color: #7ba4d9; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; }',
    '#f8w .f8dot { width: 7px; height: 7px; border-radius: 50%; background: #22c55e; display: inline-block; animation: f8pulse 2s infinite; }',
    '@keyframes f8pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }',
    '#f8w .f8card { background: #1a1f2e; border: 1px solid #2d3748; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.6rem; }',
    '#f8w .f8co { font-size: 0.88rem; font-weight: 600; color: #f0f4ff; }',
    '#f8w .f8badge { font-size: 0.65rem; font-weight: 700; padding: 1px 6px; border-radius: 3px; text-transform: uppercase; margin-left: 0.4rem; vertical-align: middle; }',
    '#f8w .f8-105 { background: #4c1d95; color: #ddd6fe; }',
    '#f8w .f8-801 { background: #164e63; color: #a5f3fc; }',
    '#f8w .f8meta { font-size: 0.72rem; color: #64748b; margin: 0.2rem 0 0.4rem; }',
    '#f8w .f8sum { font-size: 0.78rem; color: #cbd5e1; border-left: 3px solid #3b82f6; padding-left: 0.6rem; line-height: 1.5; }',
    '#f8w .f8foot { font-size: 0.68rem; color: #475569; text-align: right; margin-top: 0.75rem; }',
    '#f8w .f8foot a { color: #3b82f6; text-decoration: none; }'
  ].join(' ');

  var el = document.getElementById('form8-widget');
  if (!el) return;

  var style = document.createElement('style');
  style.textContent = STYLES;
  document.head.appendChild(style);

  el.innerHTML = '<div id="f8w"><h4><span class="f8dot"></span> SEC CyberSec Alerts</h4><div id="f8w-body">Loading...</div><div class="f8foot">Powered by <a href="https://form8.live" target="_blank">form8.live</a></div></div>';

  function safe(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function render(data) {
    var body = document.getElementById('f8w-body');
    if (!data.alerts || !data.alerts.length) {
      body.innerHTML = '<div style="color:#475569;font-size:0.8rem;padding:0.5rem">No recent filings.</div>';
      return;
    }
    body.innerHTML = data.alerts.map(function(a) {
      var is105 = (a.disclosure_type || '').indexOf('1.05') > -1 || (a.disclosure_type || '').indexOf('ITEM_1_05') > -1;
      var badge = is105
        ? '<span class="f8badge f8-105">1.05 Material</span>'
        : '<span class="f8badge f8-801">8.01 Voluntary</span>';
      var date = safe((a.filed_at || a.created_at || '').substring(0, 10));
      var ticker = safe(a.ticker || '');
      var company = safe(a.company_name || '');
      var summary = a.summary ? safe(a.summary.substring(0, 160)) + (a.summary.length > 160 ? '...' : '') : '';
      return '<div class="f8card">'
        + '<div class="f8co">' + company + badge + '</div>'
        + '<div class="f8meta">' + date + (ticker ? ' &middot; ' + ticker : '') + '</div>'
        + (summary ? '<div class="f8sum">' + summary + '</div>' : '')
        + '</div>';
    }).join('');
  }

  function load() {
    fetch(FEED)
      .then(function(r) { return r.json(); })
      .then(render)
      .catch(function() {
        var body = document.getElementById('f8w-body');
        if (body) body.innerHTML = '<div style="color:#475569;font-size:0.8rem">Unable to load alerts.</div>';
      });
  }

  load();
  setInterval(load, 60000);
})();
"""


@app.get("/widget.js")
def widget_js(key: str = Query(default="demo")) -> Response:
    """Serves the embeddable widget script."""
    js = _WIDGET_JS_TEMPLATE.replace("{{KEY}}", key.replace("'", "\\'"))
    return Response(content=js, media_type="application/javascript")


# ---------------------------------------------------------------------------
# Static mount — must remain last
# ---------------------------------------------------------------------------

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
