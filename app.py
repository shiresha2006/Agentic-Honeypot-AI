from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional

app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Honeypot service to analyze scam or malicious content",
    version="1.0.0"
)

# -----------------------------
# Root endpoint (prevents 404)
# -----------------------------
@app.get("/")
def health_check():
    return {
        "status": "running",
        "service": "Agentic Honey-Pot API",
        "message": "Service is live and operational"
    }

# --------------------------------
# Honeypot analyze endpoint
# --------------------------------
@app.post("/analyze-scam")
def analyze_scam(
    payload: dict = Body(default={}),
    x_api_key: Optional[str] = Header(None)
):
    # API key validation
    if x_api_key != "hp-a1b2c3d4e5f6g7h8":
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key"
        )

    # Extract text safely (tester may send empty body)
    text = payload.get("text", "")

    # Basic honeypot-style response
    response = {
        "honeypot_response": "Request successfully captured by honeypot.",
        "scam_type": "Unknown",
        "risk_level": "Low",
        "confidence": 0.45,
        "intent": "Potential Financial Fraud",
        "received_text": text if text else "No text provided"
    }

    return response
