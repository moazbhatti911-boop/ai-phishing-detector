"""Shared Pydantic schemas for the phishing detector."""
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """A request to analyze one user-submitted URL."""

    url: str = Field(..., min_length=1, description="The URL to analyze")


class Verdict(BaseModel):
    """An explainable verdict for one URL."""

    label: str = Field(..., description="LEGIT, SUSPICIOUS or PHISHING")
    score: int = Field(..., ge=0, le=100, description="Risk score, 0-100")
    reasons: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """One stored analysis, as returned by the API."""

    id: int
    url: str
    label: str
    score: int
    ml_probability: float
    reasons: list[str]
    created_at: str
