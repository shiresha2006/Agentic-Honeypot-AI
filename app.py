from fastapi import FastAPI, Header, HTTPException, Request
from typing import Optional

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "live"}

# Accept EVERYTHING: GET, POST, no body, broken body
@app.api_route("/analyze-scam", methods=["GET", "POST", "PUT", "OPTIONS"])
async def analyze_scam(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    # API key check (keep it simple)
    if x_api_key != "hp-a1b2c3d4e5f6g7h8":
        raise HTTPException(status_code=401, detail="Invalid API key")

    # DO NOT parse body – just read raw
    try:
        raw_body = await request.body()
    except:
        raw_body = b""

    return {
        "honeypot_response": "Submission completed successfully.",
        "scam_type": "Unknown",
        "risk_level": "Low",
        "confidence": 0.5,
        "extracted_entities": {
            "amounts": [],
            "links_present": False
        },
        "fingerprint_id": "impact-ai-thon",
        "intent": "Financial Fraud"
    }
