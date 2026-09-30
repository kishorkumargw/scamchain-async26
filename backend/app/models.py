from pydantic import BaseModel, field_validator
from typing import List, Optional


class AnalyzeRequest(BaseModel):
    messages: List[str]
    use_ai_narrative: Optional[bool] = False
    lang: Optional[str] = "en"  # "en" or "kn" - unsupported values fall back to "en" (Feature 9)

    @field_validator("messages")
    @classmethod
    def strip_and_drop_blanks(cls, v: List[str]) -> List[str]:
        # A blank/whitespace-only entry is not a real signal - drop it here
        # rather than letting it flow through as a fake "Message N" node in
        # the evidence graph. Whether anything is left after this is checked
        # in the endpoint, which returns a clear 400 rather than a 200 full
        # of nonsense if the list is empty afterwards.
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
