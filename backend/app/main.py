"""
main.py
FastAPI entrypoint. Wires steps 1-9 of the ScamChain pipeline into a single
POST /analyze endpoint that the frontend (or curl, or Postman for the demo)
calls with a list of raw messages (+ optional language) and gets back the
full evidence graph, attack chain, per-stage breakdown, timeline, and
threat story/response - already rendered in the requested language.

Run with:
    uvicorn app.main:app --reload --port 8000
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .extractor import extract_all
from .chain_classifier import build_chain
from .graph_builder import build_evidence_graph
from .explainer import build_threat_story
from .llm import generate_ai_narrative
from .models import AnalyzeRequest, AnalyzeResponse
from . import i18n
from .scenarios import SCENARIOS

logger = logging.getLogger("scamchain")

app = FastAPI(title="ScamChain API", version="0.2.0")

# Wide-open CORS for hackathon demo purposes - tighten before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/languages")
def languages():
    """So the frontend can confirm which languages the backend actually
    supports, instead of hardcoding that list twice."""
    return {"supported": sorted(i18n.SUPPORTED_LANGS), "default": i18n.DEFAULT_LANG}


@app.get("/scenarios")
def scenarios():
    """
    Feature 5 (demo scenario selector): a single source of truth for every
    synthetic demo scenario, so the frontend dropdown never hardcodes scam
    text of its own - it just lists+loads from here, same as a judge could
    via curl. Message content is intentionally English-only; see
    scenarios.py for why.
    """
    return {"scenarios": SCENARIOS}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    # req.messages has already been stripped/blank-filtered by the model's
    # validator - if nothing real is left, say so clearly instead of running
    # the pipeline on nothing and returning a confusing "attack" narrative
    # for zero input (this used to happen - see PIPELINE_FIXES.md).
    if not req.messages:
        raise HTTPException(
            status_code=400,
            detail="No usable messages were provided (list was empty, or contained only blank text).",
        )

    # Feature 9: unsupported language -> fall back to English, never error.
    lang = i18n.normalize_lang((req.lang or "en").lower())

    try:
        extracted = extract_all(req.messages)                                    # steps 1-3 (language-independent)
        chain_result = build_chain(extracted)                                     # steps 4 & 6-7 (language-independent)
        graph = build_evidence_graph(
            extracted,
            chain_result["per_message_stage"],
            lang=lang,
            stage_evidence=chain_result["stage_evidence"],
            relationships=chain_result["relationships"],
        )  # step 5
        story = build_threat_story(extracted, chain_result, lang=lang)            # steps 8-9 (localized)

        if req.use_ai_narrative:
            story = generate_ai_narrative(chain_result=chain_result, template_story=story, lang=lang)
    except Exception:
        # Never let an unexpected exception surface a raw traceback mid-demo.
        # generate_ai_narrative already fails safe on its own, so anything
        # reaching here is in the deterministic rule-based path - log it for
        # after the demo, tell the caller something sane happened instead.
        logger.exception("ScamChain pipeline failed for input of %d messages", len(req.messages))
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly. Check server logs.")

    return AnalyzeResponse(
        lang=story["lang"],
        verdict=story["verdict"],
        verdict_label=story["verdict_label"],
        narrative=story["narrative"],
        current_stage=story["current_stage"],
        current_stage_label=story["current_stage_label"],
        risk_level=story["risk_level"],
        risk_level_label=story["risk_level_label"],
        risk_reason=story["risk_reason"],
        evidence=story["evidence"],
        inference=story["inference"],
        recommendation=story["recommendation"],
        stage_breakdown=story["stage_breakdown"],
        response=story["response"],
        chain=chain_result["chain"],
        per_message_stage=chain_result["per_message_stage"],
        relationships=chain_result["relationships"],
        message_contributions=chain_result["message_contributions"],
        evidence_summary=chain_result["evidence_summary"],
        graph=graph,
        timeline=story["timeline"],
    )
