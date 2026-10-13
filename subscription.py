"""
NeuroSim — Subscription & Test Drive
====================================
Adds to the existing FastAPI app:

  GET  /subscription         — subscription page (subscription.html)
  POST /trial/start          — issue a 120-second test-drive token (1 per IP per 24 h)
  POST /trial/simulate       — run a simulation with a valid, unexpired trial token
  POST /subscribe/apply      — tier application with server-side verification filters
  GET  /subscribe/tiers      — tier catalog (prices, limits, verification rules)

Verification filters (enforced server-side, not just in the browser):
  * Email domain must match the tier (corporate for Pharma/AI; .edu/.ac/.gov for
    Research and Education); free-mail domains are rejected for every tier.
  * Website / GitHub org must match the email domain (Pharma, AI) or the
    application drops to manual review.
  * Discounted tiers (Research, AI, Education) require an affiliation document
    (affiliation letter, student ID, or company registration).
  * Seat caps per tier; Education carries no commercial rights.
  * Terms acceptance (audit rights, termination for misrepresentation, annual
    true-up) is mandatory.

Configuration (Render → Environment):
  NEUROSIM_SECRET      HMAC key for trial tokens (set it; a random key is used otherwise
                       and tokens are invalidated on every restart)
  NEUROSIM_DATA_DIR    where applications + uploads are written (default ./data)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, NOTIFY_EMAIL
                       optional — when set, each application (with attachment)
                       is emailed to NOTIFY_EMAIL

Author : Alex Osterneck, CLA, MSCS, MSIT — NeuroSim
"""


import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import time
import uuid
from email.message import EmailMessage
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse

# ── Settings ──────────────────────────────────────────────────────────────────

TRIAL_SECONDS = 120
TRIAL_MAX_RUNS = 25                 # simulations allowed inside one test drive
TRIAL_MAX_DURATION_MIN = 480        # same ceiling as the homepage slider
TRIAL_COOLDOWN_SECONDS = 24 * 3600  # one test drive per IP per 24 h
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_UPLOAD_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".docx"}

SECRET = os.environ.get("NEUROSIM_SECRET", "").encode() or secrets.token_bytes(32)
DATA_DIR = os.environ.get("NEUROSIM_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "yahoo.co.uk", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "yandex.com",
    "yandex.ru", "zoho.com", "qq.com", "163.com", "126.com", "comcast.net", "verizon.net",
    "att.net", "sbcglobal.net", "cox.net", "tutanota.com", "fastmail.com", "hey.com",
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
}

# Tier catalog — single source of truth for prices, limits and verification rules.
TIERS = {
    "pharma": {
        "name": "Pharma / Drug Developers",
        "segment": "QSP, in silico testing, endocrine modeling",
        "plans": {
            "site": {"label": "Enterprise", "annual": 30000, "monthly": 2750},
        },
        "seats_max": 25,
        "domain_rule": "corporate",
        "doc_required": False,
        "commercial": True,
    },
    "research": {
        "name": "Computational Neuroscience / Endocrinology",
        "segment": "Academic & institute research labs",
        "plans": {
            "lab": {"label": "Lab", "annual": 8000, "monthly": 750},
            "individual": {"label": "Individual researcher", "annual": 4800, "monthly": 450},
        },
        "seats_max": 5,
        "domain_rule": "academic_or_institute",
        "doc_required": True,
        "commercial": False,
    },
    "ai": {
        "name": "AI & Cognitive Architecture Developers",
        "segment": "Agent, affect and cognitive-model teams",
        "plans": {
            "team": {"label": "Team", "annual": 3600, "monthly": 350},
        },
        "seats_max": 3,
        "domain_rule": "corporate",
        "doc_required": True,
        "commercial": False,
    },
    "education": {
        "name": "Educators & Institutions",
        "segment": "Medical simulation & teaching",
        "plans": {
            "seat": {"label": "Per seat", "annual": 150, "monthly": None},
            "institution": {"label": "Institutional", "annual": 6000, "monthly": None},
        },
        "seats_max": 500,
        "domain_rule": "academic",
        "doc_required": True,
        "commercial": False,
    },
}

ACADEMIC_RE = re.compile(r"(\.edu|\.edu\.[a-z]{2}|\.ac\.[a-z]{2}|\.gov|\.gov\.[a-z]{2}|\.mil)$")

# ── In-memory trial ledger (resets on restart; fine for a single Render instance) ─

_trial_by_ip: dict[str, float] = {}   # ip_hash -> issued_at
_trial_runs: dict[str, int] = {}      # jti -> runs used


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown"))


def _ip_hash(ip: str) -> str:
    return hmac.new(SECRET, ip.encode(), hashlib.sha256).hexdigest()[:24]


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: dict) -> str:
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _verify(token: str) -> dict:
    try:
        body, sig = token.split(".", 1)
        good = _b64(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            raise ValueError
        return json.loads(_unb64(body))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid test-drive token.")


# ── Verification helpers ──────────────────────────────────────────────────────

def _email_domain(email: str) -> str:
    email = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return email.split("@", 1)[1]


def _registrable(domain: str) -> str:
    """Rough registrable domain: last two labels, or last three for 2-letter SLD ccTLDs."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "ac", "edu", "gov", "com", "org", "net"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _url_host(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


def check_domain(tier_key: str, domain: str) -> tuple[bool, str]:
    """Returns (passes, note). Raises 422 on hard rejection."""
    rule = TIERS[tier_key]["domain_rule"]
    if domain in FREEMAIL or _registrable(domain) in FREEMAIL:
        raise HTTPException(status_code=422,
            detail="Personal email domains are not accepted. Use your company or institutional email.")
    academic = bool(ACADEMIC_RE.search(domain))
    if rule == "academic":
        if not academic:
            raise HTTPException(status_code=422,
                detail="Education plans require an institutional email (.edu, .ac.xx, or .gov).")
        return True, "academic domain"
    if rule == "academic_or_institute":
        if academic:
            return True, "academic domain"
        return False, "non-academic research domain — manual review"
    # corporate
    if academic:
        return False, "academic domain on a commercial tier — manual review"
    return True, "corporate domain"


# ── Persistence & notification ────────────────────────────────────────────────

def _save(app_id: str, record: dict, upload: Optional[tuple[str, bytes]]) -> None:
    folder = os.path.join(DATA_DIR, "applications", app_id)
    os.makedirs(folder, exist_ok=True)
    if upload:
        with open(os.path.join(folder, upload[0]), "wb") as f:
            f.write(upload[1])
    with open(os.path.join(folder, "application.json"), "w") as f:
        json.dump(record, f, indent=2)


def _notify(record: dict, upload: Optional[tuple[str, bytes]]) -> bool:
    host, to = os.environ.get("SMTP_HOST"), os.environ.get("NOTIFY_EMAIL")
    if not (host and to):
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = (f"NeuroSim application {record['id']} — {record['tier_name']} "
                          f"[{record['status']}]")
        msg["From"] = os.environ.get("SMTP_USER", to)
        msg["To"] = to
        msg["Reply-To"] = record["email"]
        msg.set_content(json.dumps(record, indent=2))
        if upload:
            msg.add_attachment(upload[1], maintype="application", subtype="octet-stream",
                               filename=upload[0])
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=20) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
            s.send_message(msg)
        return True
    except Exception:
        return False


# ── Router ────────────────────────────────────────────────────────────────────

def build_router(simulate_fn, SimulateRequest) -> APIRouter:
    router = APIRouter()

    @router.get("/subscription", response_class=HTMLResponse)
    def subscription_page():
        path = os.path.join(os.path.dirname(__file__), "subscription.html")
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())

    @router.get("/subscribe/tiers")
    def tiers():
        return {"tiers": TIERS, "trial_seconds": TRIAL_SECONDS}

    @router.post("/trial/start")
    def trial_start(request: Request):
        now = time.time()
        iph = _ip_hash(_client_ip(request))
        last = _trial_by_ip.get(iph)
        if last and now - last < TRIAL_COOLDOWN_SECONDS:
            wait_h = int((TRIAL_COOLDOWN_SECONDS - (now - last)) // 3600) + 1
            raise HTTPException(status_code=429,
                detail=f"Test drive already used from this network. Available again in ~{wait_h} h.")
        _trial_by_ip[iph] = now
        jti = uuid.uuid4().hex
        exp = now + TRIAL_SECONDS
        _trial_runs[jti] = 0
        return {"token": _sign({"jti": jti, "iph": iph, "exp": exp}),
                "expires_in": TRIAL_SECONDS, "max_runs": TRIAL_MAX_RUNS}

    @router.post("/trial/simulate")
    def trial_simulate(req: SimulateRequest, request: Request,
                       x_trial_token: str = Header(default="")):
        if not x_trial_token:
            raise HTTPException(status_code=401, detail="Start a test drive first.")
        claims = _verify(x_trial_token)
        if time.time() > claims["exp"]:
            raise HTTPException(status_code=403, detail="Test drive ended. Choose a plan to continue.")
        if claims["iph"] != _ip_hash(_client_ip(request)):
            raise HTTPException(status_code=403, detail="Test-drive token is tied to the network that started it.")
        used = _trial_runs.get(claims["jti"], TRIAL_MAX_RUNS)
        if used >= TRIAL_MAX_RUNS:
            raise HTTPException(status_code=403, detail="Test-drive run limit reached.")
        if req.duration_minutes > TRIAL_MAX_DURATION_MIN:
            raise HTTPException(status_code=422, detail=f"Test drive is capped at {TRIAL_MAX_DURATION_MIN} min.")
        _trial_runs[claims["jti"]] = used + 1
        result = simulate_fn(req)
        result["trial"] = {"seconds_left": max(0, int(claims["exp"] - time.time())),
                           "runs_left": TRIAL_MAX_RUNS - used - 1}
        return result

    @router.post("/subscribe/apply")
    async def apply(
        tier: str = Form(...),
        plan: str = Form(...),
        billing: str = Form("annual"),
        full_name: str = Form(...),
        email: str = Form(...),
        organization: str = Form(...),
        role: str = Form(""),
        website: str = Form(""),
        seats: int = Form(1),
        use_case: str = Form(""),
        accept_terms: str = Form(""),
        accept_trueup: str = Form(""),
        document: Optional[UploadFile] = File(None),
    ):
        if tier not in TIERS:
            raise HTTPException(status_code=422, detail="Unknown tier.")
        t = TIERS[tier]
        if plan not in t["plans"]:
            raise HTTPException(status_code=422, detail="Unknown plan for this tier.")
        p = t["plans"][plan]
        if billing not in ("annual", "monthly") or (billing == "monthly" and not p["monthly"]):
            raise HTTPException(status_code=422, detail="This plan is billed annually only.")
        if accept_terms != "yes" or accept_trueup != "yes":
            raise HTTPException(status_code=422,
                detail="Accept the Terms (audit rights, termination for misrepresentation) and the annual true-up.")
        if not full_name.strip() or not organization.strip():
            raise HTTPException(status_code=422, detail="Name and organization are required.")
        if seats < 1 or seats > t["seats_max"]:
            raise HTTPException(status_code=422, detail=f"{t['name']} allows 1–{t['seats_max']} seats.")
        if tier == "research" and plan == "individual" and seats != 1:
            raise HTTPException(status_code=422, detail="Individual researcher plan is one seat.")

        domain = _email_domain(email)
        domain_ok, domain_note = check_domain(tier, domain)
        reasons = [] if domain_ok else [domain_note]

        # Website / GitHub org must match the email domain on commercial-style tiers.
        site_host = _url_host(website)
        if tier in ("pharma", "ai"):
            if not site_host:
                raise HTTPException(status_code=422, detail="Company website (or GitHub org URL) is required.")
            if site_host.endswith("github.com"):
                reasons.append("GitHub org supplied instead of company site — manual review")
            elif _registrable(site_host) != _registrable(domain):
                reasons.append(f"website {site_host} does not match email domain {domain} — manual review")

        # Affiliation document for discounted tiers.
        upload = None
        if document is not None and document.filename:
            ext = os.path.splitext(document.filename)[1].lower()
            if ext not in ALLOWED_UPLOAD_EXT:
                raise HTTPException(status_code=422, detail="Upload PDF, PNG, JPG or DOCX.")
            data = await document.read()
            if len(data) > MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=422, detail="Upload must be 8 MB or smaller.")
            upload = (f"affiliation{ext}", data)
        if t["doc_required"] and upload is None:
            raise HTTPException(status_code=422,
                detail="Upload proof of affiliation (letter, student/faculty ID, or company registration).")
        if upload is not None:
            reasons.append("affiliation document — reviewer check")

        price = p["annual"] if billing == "annual" else p["monthly"]
        if tier == "education" and plan == "seat":
            price = p["annual"] * seats

        app_id = "NS-" + time.strftime("%y%m%d") + "-" + uuid.uuid4().hex[:6].upper()
        status = "pending_review" if reasons else "verified_pending_invoice"
        record = {
            "id": app_id, "submitted_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": status, "review_reasons": reasons,
            "tier": tier, "tier_name": t["name"], "plan": plan, "plan_label": p["label"],
            "billing": billing, "price_usd": price, "seats": seats,
            "commercial_rights": t["commercial"],
            "full_name": full_name.strip(), "email": email.strip().lower(), "email_domain": domain,
            "organization": organization.strip(), "role": role.strip(), "website": website.strip(),
            "use_case": use_case.strip()[:2000], "document": upload[0] if upload else None,
            "terms_accepted": True, "trueup_accepted": True,
        }
        _save(app_id, record, upload)
        emailed = _notify(record, upload)
        return {"id": app_id, "status": status, "price_usd": price, "billing": billing,
                "review_reasons": reasons, "notified": emailed}

    return router
