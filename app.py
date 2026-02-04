"""
Agentic Honey-Pot API (FastAPI version)
=========================================
Accepts scam messages and returns extracted threat intelligence.
Secured with API-key authentication via X-API-Key header.
"""

import os
import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# App initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Honeypot service to analyze scam messages and extract intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.environ.get("API_KEY", "hp-a1b2c3d4e5f6g7h8")

# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------
class HoneypotRequest(BaseModel):
    message: str

class EntityExtraction(BaseModel):
    emails: list[str]
    urls: list[str]
    phone_numbers: list[str]
    crypto_wallets: list[str]

class Intelligence(BaseModel):
    scam_type: str
    threat_level: str
    indicators: list[str]
    extracted_entities: EntityExtraction
    summary: str

class HoneypotResponse(BaseModel):
    status: str
    request_id: str
    timestamp: str
    message_hash: str
    intelligence: Intelligence

# ---------------------------------------------------------------------------
# Scam-pattern dictionaries
# ---------------------------------------------------------------------------
SCAM_KEYWORDS = {
    "phishing": ["click here", "verify your account", "confirm your identity",
                 "update your payment", "login here", "your account will be",
                 "suspended", "unusual activity", "confirm your details",
                 "secure your account", "limited time offer", "act now"],
    "romance": ["fallen in love", "need financial help", "overseas deployment",
                "military officer", "doctor abroad", "trust you with",
                "inheritance", "send money", "wire transfer", "gift cards"],
    "investment": ["guaranteed returns", "double your money", "exclusive opportunity",
                   "high returns", "low risk", "insider tip", "crypto investment",
                   "get rich quick", "passive income", "financial freedom"],
    "lottery": ["you have won", "claim your prize", "lottery winner",
                "selected as winner", "free iphone", "congratulations you won"],
    "tech_support": ["your computer is infected", "call our support",
                     "remote access", "virus detected", "your device is compromised",
                     "microsoft support", "apple support", "tech support"],
    "impersonation": ["i am from your bank", "irs agent", "police officer",
                      "government agent", "your social security", "tax refund",
                      "irs notice", "dea agent"]
}

URGENCY_PHRASES = [
    "act now", "immediately", "urgent", "limited time", "expires soon",
    "within 24 hours", "don't wait", "time is running out", "asap",
    "right away", "before it's too late", "last chance"
]

THREAT_INDICATORS = [
    "click", "link", "download", "wire", "gift card", "bitcoin",
    "crypto", "western union", "money gram", "bank transfer",
    "social security", "credit card", "password", "ssn", "pin"
]

# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
URL_RE = re.compile(r'https?://[^\s<>"{}|\\^`\[\],;)>]+')
PHONE_RE = re.compile(r'[\+]?[\d][\d\s\-\(\)]{7,}\d')
CRYPTO_RE = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[0-9a-fA-F]{40}\b')


def extract_entities(text: str) -> EntityExtraction:
    """Pull structured entities from raw scam text."""
    return EntityExtraction(
        emails=list(set(EMAIL_RE.findall(text))),
        urls=list(set(URL_RE.findall(text))),
        phone_numbers=list(set(PHONE_RE.findall(text))),
        crypto_wallets=list(set(CRYPTO_RE.findall(text)))
    )


def detect_scam_type(text: str) -> str:
    """Return the best-matching scam category (or 'unknown')."""
    lower = text.lower()
    best_type, best_score = "unknown", 0
    for stype, keywords in SCAM_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in lower)
        if score > best_score:
            best_type, best_score = stype, score
    return best_type


def compute_threat_level(text: str, scam_type: str) -> str:
    """Score the message and bucket into LOW / MEDIUM / HIGH / CRITICAL."""
    lower = text.lower()
    score = 0
    # Urgency
    score += sum(2 for p in URGENCY_PHRASES if p in lower)
    # Known scam type hit
    if scam_type != "unknown":
        score += 3
    # Threat indicators
    score += sum(1 for ind in THREAT_INDICATORS if ind in lower)
    # Entity richness — more IOCs → more dangerous
    entities = extract_entities(text)
    score += len(entities.urls) * 2
    score += len(entities.emails)
    score += len(entities.crypto_wallets) * 3

    if score >= 12: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 3: return "MEDIUM"
    return "LOW"


def find_indicators(text: str) -> list[str]:
    """Return every matched threat indicator present in the message."""
    lower = text.lower()
    return [ind for ind in THREAT_INDICATORS if ind in lower]


def generate_summary(text: str, scam_type: str, threat_level: str) -> str:
    """Build a concise intelligence summary."""
    type_map = {
        "phishing": "a phishing attempt designed to steal credentials or personal data",
        "romance": "a romance scam designed to build emotional trust before requesting funds",
        "investment": "an investment scam promising fraudulent financial returns",
        "lottery": "a lottery/prize scam falsely claiming the victim has won money",
        "tech_support": "a tech-support scam attempting to gain remote device access",
        "impersonation": "an impersonation scam posing as a trusted authority"
    }
    desc = type_map.get(scam_type, "a scam of unknown classification")
    return (
        f"[{threat_level}] The message is {desc}. "
        f"Threat level assessed as {threat_level} based on urgency cues, "
        f"indicator density, and extracted IOCs. Immediate flagging recommended."
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    """Root endpoint - service status."""
    return {
        "status": "ok",
        "service": "Agentic Honey-Pot API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/health")
def health():
    """Public health-check — no auth required."""
    return {
        "status": "ok",
        "service": "Agentic Honey-Pot API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/honeypot", response_model=HoneypotResponse)
def honeypot(
    request: HoneypotRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    """
    Main endpoint - accepts scam messages and returns intelligence.
    Requires X-API-Key header for authentication.
    """
    # --- Authentication ---
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized. Provide a valid X-API-Key header."
        )

    # --- Validation ---
    message = request.message.strip()
    if not message:
        raise HTTPException(
            status_code=400,
            detail="Field 'message' is required and must be non-empty."
        )

    # --- Extraction pipeline ---
    scam_type = detect_scam_type(message)
    entities = extract_entities(message)
    indicators = find_indicators(message)
    threat_level = compute_threat_level(message, scam_type)
    summary = generate_summary(message, scam_type, threat_level)
    msg_hash = hashlib.sha256(message.encode()).hexdigest()

    # --- Response ---
    return HoneypotResponse(
        status="success",
        request_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        message_hash=msg_hash,
        intelligence=Intelligence(
            scam_type=scam_type,
            threat_level=threat_level,
            indicators=indicators,
            extracted_entities=entities,
            summary=summary
        )
    )


# ---------------------------------------------------------------------------
# Entry point (for local testing with uvicorn)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
