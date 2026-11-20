"""FastAPI server for the AI-Based Phishing Detection System.

Runs on 127.0.0.1:8004. Only URLs the user submits are analyzed; the
page HTML is fetched (short timeout) only for a submitted URL, and when
the fetch fails the URL is analyzed from its URL features alone.
"""
from contextlib import asynccontextmanager

import httpx
from fastapi import Depends, FastAPI, HTTPException

from detector.verdict import analyze_url
from shared.schemas import AnalyzeRequest, AnalysisResult
from server.auth import verify_api_key
from server.storage import get_analysis, get_stats, init_db, insert_analysis, list_analyses

FETCH_TIMEOUT = 5.0
MAX_HTML_BYTES = 200_000


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AI-Based Phishing Detection System",
    version="1.0.0",
    lifespan=lifespan,
)


def _fetch_html(url: str) -> str | None:
    """Fetch a submitted URL's HTML, or None when it cannot be fetched."""
    try:
        with httpx.Client(
            timeout=FETCH_TIMEOUT, follow_redirects=True, trust_env=False
        ) as client:
            resp = client.get(
                url, headers={"User-Agent": "PhishingDetector/1.0 (lab)"}
            )
            content_type = resp.headers.get("content-type", "")
            if resp.status_code == 200 and "text/html" in content_type:
                return resp.text[:MAX_HTML_BYTES]
    except Exception:
        return None
    return None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", dependencies=[Depends(verify_api_key)])
def analyze(req: AnalyzeRequest):
    """Analyze one user-submitted URL and store the result."""
    html = _fetch_html(req.url)
    result = analyze_url(req.url, html=html)
    record_id, created_at = insert_analysis(
        url=req.url,
        label=result["label"],
        score=result["score"],
        ml_probability=result["ml_probability"],
        reasons=result["reasons"],
        features=result["url_features"],
    )
    return AnalysisResult(
        id=record_id,
        url=req.url,
        label=result["label"],
        score=result["score"],
        ml_probability=result["ml_probability"],
        reasons=result["reasons"],
        created_at=created_at,
    )


@app.get("/analyze/{analysis_id}", dependencies=[Depends(verify_api_key)])
def analyze_by_id(analysis_id: int):
    """Fetch one stored analysis by id."""
    row = get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisResult(
        id=row["id"],
        url=row["url"],
        label=row["label"],
        score=row["score"],
        ml_probability=row["ml_probability"],
        reasons=row["reasons"],
        created_at=row["created_at"],
    )


@app.get("/history", dependencies=[Depends(verify_api_key)])
def history(limit: int = 50):
    """Newest analyses first (default 50)."""
    rows = list_analyses(limit=limit)
    return [
        AnalysisResult(
            id=r["id"],
            url=r["url"],
            label=r["label"],
            score=r["score"],
            ml_probability=r["ml_probability"],
            reasons=r["reasons"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@app.get("/stats", dependencies=[Depends(verify_api_key)])
def stats():
    """Counts by verdict label, plus the total."""
    return get_stats()
