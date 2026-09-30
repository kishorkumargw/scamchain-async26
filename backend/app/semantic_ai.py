"""
semantic_ai.py
Optional Gemini semantic cross-check for ScamChain.

The deterministic extractor/classifier remains authoritative. This module
only asks Gemini for a structured, independent semantic interpretation of
messages and compares its candidate stage with ScamChain's computed stage.
If the API is unavailable, the deterministic pipeline continues unchanged.
"""

import os
from typing import List, Optional

from pydantic import BaseModel, Field


STAGES = ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"]


class SemanticSignal(BaseModel):
    type: str = Field(description="Short signal family, e.g. urgency, impersonation, redirect, extraction")
    evidence: str = Field(description="Short exact or near-exact phrase from the input supporting the signal")


class SemanticAnalysis(BaseModel):
    signals: List[SemanticSignal] = Field(default_factory=list)
    intent: Optional[str] = None
    stage_candidate: str = Field(default="CONTACT")
    summary: str = ""


def _fallback(reason: str, deterministic_stage: str) -> dict:
    return {
        "status": "disabled",
        "provider": "Gemini",
        "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite"),
        "stage_candidate": None,
        "deterministic_stage": deterministic_stage,
        "agreement": None,
        "signals": [],
        "intent": None,
        "summary": reason,
    }


def semantic_ai_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def cross_check(messages: List[str], deterministic_stage: str, lang: str = "en") -> dict:
    """Return a safe structured result; never raise into /analyze."""
    if not semantic_ai_available():
        return _fallback(
            "Semantic AI is disabled. Set GEMINI_API_KEY to enable the optional cross-check; deterministic ScamChain reasoning is still fully active.",
            deterministic_stage,
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
        language = "English" if lang == "en" else "simple everyday Kannada"

        numbered = "\n".join(f"Message {i + 1}: {m}" for i, m in enumerate(messages))
        prompt = f"""You are a defensive cybersecurity analyst performing an INDEPENDENT semantic cross-check.
Analyze the messages below for social-engineering signals. Do not provide instructions for committing fraud.
Do not invent entities, URLs, events, or facts. Evidence in your output must be supported by the messages.
Choose exactly one candidate stage from: {', '.join(STAGES)}.
Use {language} for the summary. Keep the summary to 1-2 sentences.

Messages:
{numbered}
"""

        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0,
                response_mime_type="application/json",
                response_schema=SemanticAnalysis,
            ),
        )

        parsed = SemanticAnalysis.model_validate_json(response.text)
        candidate = parsed.stage_candidate if parsed.stage_candidate in STAGES else "CONTACT"
        return {
            "status": "enabled",
            "provider": "Gemini",
            "model": model,
            "stage_candidate": candidate,
            "deterministic_stage": deterministic_stage,
            "agreement": candidate == deterministic_stage,
            "signals": [s.model_dump() for s in parsed.signals[:8]],
            "intent": parsed.intent,
            "summary": parsed.summary,
        }
    except Exception as exc:
        return {
            "status": "error",
            "provider": "Gemini",
            "model": os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite"),
            "stage_candidate": None,
            "deterministic_stage": deterministic_stage,
            "agreement": None,
            "signals": [],
            "intent": None,
            "summary": "Semantic AI was unavailable, so the deterministic ScamChain result was kept unchanged.",
            "error_type": type(exc).__name__,
        }
