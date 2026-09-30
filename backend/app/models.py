from typing import List, Optional

from pydantic import BaseModel, field_validator


class AnalyzeRequest(BaseModel):
    messages: List[str]
    lang: Optional[str] = "en"  # "en" or "kn" - unsupported values fall back to "en"

    @field_validator("messages")
    @classmethod
    def strip_and_drop_blanks(cls, v: List[str]) -> List[str]:
        # A blank/whitespace-only entry is not a real signal.
        return [m.strip() for m in v if m.strip()]


class AnalyzeResponse(BaseModel):
    lang: str
    verdict: str
    verdict_label: str
    narrative: str
    current_stage: str
    current_stage_label: str
    risk_level: str
    risk_level_label: str
    risk_reason: str
    evidence: List[str]
    inference: List[str]
    recommendation: List[str]
    stage_breakdown: List[dict]
    response: dict
    chain: List[str]
    per_message_stage: List[dict]
    relationships: List[dict]
    message_contributions: List[dict]
    evidence_summary: dict
    graph: dict
    timeline: List[dict]
