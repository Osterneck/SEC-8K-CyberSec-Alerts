"""FastAPI web layer for CyberSec Alerts."""

from __future__ import annotations

import json
import logging
import os
import secrets
import smtplib
from contextlib import asynccontextmanager
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import stripe
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
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

# ---------------------------------------------------------------------------
# Stripe price IDs — set in Render environment variables
# ---------------------------------------------------------------------------
PRICE_IDS = {
    "individual": os.environ.get("STRIPE_PRICE_INDIVIDUAL", "price_INDIVIDUAL"),
    "team":       os.environ.get("STRIPE_PRICE_TEAM",       "price_TEAM"),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE", "price_ENTERPRISE"),
}

TIER_LABELS = {
    "individual": "Individual — $999/yr",
    "team":       "Team — $2,499/yr",
    "enterprise": "Enterprise — $4,999/yr",
}

SITE_URL = os.environ.get("SITE_URL", "https://form8.live")


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
    # Configure Stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe.api_key:
        LOGGER.warning("STRIPE_SECRET_KEY not set — payments disabled.")
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
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Alert helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: Any) -> dict[str, Any]:
    d = dict(row)
    for field in ("exposures_json", "signals_json", "enforcement_json"):
        if field in d and d[field]:
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
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="SEC_USER_AGENT not configured.")
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    new_alerts = _pipeline.run_once_structured(limit=limit, enforcement_pages=enforcement_pages)
    rows = _store.recent_alerts(limit=20)
    return {
        "source": "live",
        "new_alerts": len(new_alerts),
        "new_alert_accessions": [a.incident.filing.accession for a in new_alerts],
        "alerts": [_row_to_dict(r) for r in rows],
    }


@app.get("/api/history")
def history(limit: int = Query(default=20, ge=1, le=200)) -> dict[str, Any]:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    rows = _store.recent_alerts(limit=limit)
    return {"count": len(rows), "alerts": [_row_to_dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Widget feed — API-key gated
# ---------------------------------------------------------------------------

@app.get("/api/widget-feed")
def widget_feed(
    key: str = Query(default=""),
    limit: int = Query(default=5, ge=1, le=20),
) -> dict[str, Any]:
    if _store is None:
        raise HTTPException(status_code=503, detail="Store not initialised.")
    # Enforce API key — "demo" allowed for trial/preview only
    if key and key != "demo":
        sub = _store.get_subscriber_by_key(key)
        if sub is None:
            raise HTTPException(status_code=403, detail="Invalid API key.")
    rows = _store.recent_alerts(limit=limit)
    return {"count": len(rows), "alerts": [_row_to_dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Widget JS
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
      var is105 = (a.disclosure_type || '').toLowerCase().indexOf('item_1_05') > -1 || (a.disclosure_type || '').indexOf('1.05') > -1;
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
    js = _WIDGET_JS_TEMPLATE.replace("{{KEY}}", key.replace("'", "\\'"))
    return Response(content=js, media_type="application/javascript")


# ---------------------------------------------------------------------------
# Stripe Checkout
# ---------------------------------------------------------------------------

@app.post("/api/create-checkout-session")
async def create_checkout_session(request: Request) -> JSONResponse:
    """Creates a Stripe Checkout session for the selected tier."""
    if not stripe.api_key:
        raise HTTPException(status_code=503, detail="Payments not configured.")
    body = await request.json()
    tier = body.get("tier", "individual").lower()
    if tier not in PRICE_IDS:
        raise HTTPException(status_code=400, detail=f"Unknown tier: {tier}")
    price_id = PRICE_IDS[tier]
    if price_id.startswith("price_INDIVIDUAL") or price_id.startswith("price_TEAM") or price_id.startswith("price_ENTERPRISE"):
        raise HTTPException(status_code=503, detail="Stripe price IDs not yet configured. Check back soon.")
    try:
        session = stripe.checkout.Session.create(
            mode="payment",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"{SITE_URL}/success.html?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{SITE_URL}/subscribe.html?cancelled=1",
            metadata={"tier": tier},
        )
        return JSONResponse({"url": session.url})
    except stripe.error.StripeError as e:
        LOGGER.error("Stripe error: %s", e)
        raise HTTPException(status_code=502, detail=str(e))


# ---------------------------------------------------------------------------
# Stripe Webhook
# ---------------------------------------------------------------------------

@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request) -> JSONResponse:
    """Handles Stripe checkout.session.completed webhook."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    if not webhook_secret:
        LOGGER.warning("STRIPE_WEBHOOK_SECRET not set — skipping signature verification.")
        event = json.loads(payload)
    else:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid webhook signature.")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        email = session.get("customer_details", {}).get("email", "")
        tier = session.get("metadata", {}).get("tier", "individual")
        session_id = session.get("id", "")

        if not email:
            LOGGER.warning("Webhook: no email in session %s", session_id)
            return JSONResponse({"status": "no_email"})

        api_key = "f8_" + secrets.token_urlsafe(32)

        if _store:
            _store.add_subscriber(
                email=email,
                tier=tier,
                api_key=api_key,
                stripe_session_id=session_id,
            )
            LOGGER.info("New subscriber: %s tier=%s", email, tier)

        _send_api_key_email(email=email, tier=tier, api_key=api_key)

    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Email delivery
# ---------------------------------------------------------------------------

def _send_api_key_email(email: str, tier: str, api_key: str) -> None:
    smtp_host = os.environ.get("SMTP_HOST", "mail.privateemail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "info@form8.live")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    tier_label = TIER_LABELS.get(tier, tier.title())
    embed_snippet = (
        f'<div id="form8-widget"></div>\n'
        f'<script src="https://form8.live/widget.js?key={api_key}" async></script>'
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Georgia,serif;background:#0f1117;color:#e2e8f0;padding:2rem;max-width:600px;margin:0 auto">
  <div style="background:#1a1f2e;border:1px solid #2d3748;border-radius:8px;padding:2rem">
    <h2 style="color:#f0f4ff;margin-bottom:0.5rem">SEC CyberSec Alerts</h2>
    <p style="color:#64748b;font-size:0.85rem;margin-bottom:1.5rem">form8.live</p>

    <p>Thank you for subscribing to <strong style="color:#dbeafe">{tier_label}</strong>.</p>
    <p>Your API key is ready:</p>

    <div style="background:#0f1117;border:1px solid #2d3748;border-radius:6px;padding:1rem;margin:1rem 0;font-family:monospace;font-size:0.9rem;color:#22c55e;word-break:break-all">
      {api_key}
    </div>

    <p style="font-size:0.85rem;color:#94a3b8">To embed the live widget on your site, paste this into your HTML:</p>
    <pre style="background:#0f1117;border:1px solid #2d3748;border-radius:6px;padding:1rem;font-size:0.78rem;color:#7ba4d9;overflow-x:auto;white-space:pre-wrap">{embed_snippet}</pre>

    <hr style="border-color:#2d3748;margin:1.5rem 0">
    <p style="font-size:0.75rem;color:#475569">
      Questions? Reply to this email or contact us at info@form8.live.<br>
      Keep your API key confidential — it controls access to your widget feed.
    </p>
  </div>
</body>
</html>
"""
    text_body = (
        f"Thank you for subscribing to SEC CyberSec Alerts — {tier_label}.\n\n"
        f"Your API key: {api_key}\n\n"
        f"Embed snippet:\n{embed_snippet}\n\n"
        f"Questions? Email info@form8.live"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your SEC CyberSec Alerts API Key"
    msg["From"] = smtp_user
    msg["To"] = email
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [email], msg.as_string())
        LOGGER.info("API key email sent to %s", email)
    except Exception as exc:
        LOGGER.error("Failed to send email to %s: %s", email, exc)


# ---------------------------------------------------------------------------
# Static mount — must remain last
# ---------------------------------------------------------------------------

_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
