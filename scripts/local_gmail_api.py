
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.main import analyzer

EXTENSION_ID = os.environ.get(
    "PHISHY_EXTENSION_ID",
    "kjpdafcdcnneekokjnhkdofjckdmjpmb",
).strip()

EXTENSION_ORIGIN = f"chrome-extension://{EXTENSION_ID}"

app = FastAPI(
    title="Phishy Local Gmail Analyzer",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[EXTENSION_ORIGIN],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


class EmailPayload(BaseModel):
    sender: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1000)
    text: str = Field(min_length=1, max_length=5000)


@app.get("/health")
def health():
    return {"status": "ok", "analyzer": "local"}


@app.post("/analyze")
def analyze_email(payload: EmailPayload, request: Request):
    origin = request.headers.get("origin", "")

    if origin != EXTENSION_ORIGIN:
        raise HTTPException(
            status_code=403,
            detail="Untrusted extension origin.",
        )

    try:
        result = analyzer.analyze_message(
            text=payload.text,
            sender=payload.sender,
            subject=payload.subject,
            mode="cascade",
        )

        return {
            "risk": result.risk,
            "probability": result.probability,
            "label": result.label,
            "recommended_action": result.recommended_action,
            "evidence": result.evidence,
            "guidance": result.guidance,
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Local email analysis failed.",
        )


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765,
        log_level="info",
    )
