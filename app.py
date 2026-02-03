from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI()

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "Agentic Honey-Pot API"
    }

# ✅ Accept BOTH GET and POST
@app.api_route("/analyze-scam", methods=["GET", "POST"])
def analyze_scam(x_api_key: Optional[str] = Header(None)):
    if x_api_key != "hp-a1b2c3d4e5f6g7h8":
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "honeypot_response": "Submission completed successfully.",
        "scam_type": "Unknown",
        "risk_level": "Low",
        "confidence": 0.5,
        "extracted_entities": {
            "amounts": [],
            "links_present": False
        },
        "fingerprint_id": "auto-generated",
        "intent": "Financial Fraud"
    }
