"""
llm.py
Optional AI-powered enhancement layer. This is what lets you truthfully
call the project "AI-powered" for the judges: the structured evidence
(signals, entities, stage-by-stage chain) produced by the rule-based
pipeline is handed to Claude, which is asked only to narrate it more
naturally and sanity-check the reasoning - it is NOT relied on to do the
core detection, so the system still works (and stays explainable) if the
API is unavailable during the demo.

Set the ANTHROPIC_API_KEY environment variable to enable this. If it is
missing, callers should fall back to explainer.build_threat_story().
"""

import os
import re
import json


def is_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def generate_ai_narrative(chain_result: dict, template_story: dict, lang: str = "en") -> dict:
    """
    Best-effort call to Claude to produce a more natural NARRATIVE on top of
    the already-computed, trustworthy structured result. Deliberately only
    ever touches the "narrative" field - risk_level, stage_breakdown,
    evidence, and the response (what/why/what-to-do) block always stay the
    deterministic, rule-based values (Feature 7: LLM-assisted interpretation
    must stay clearly separate from, and never replace, the deterministic
    evidence/decision logic). Returns template_story unchanged if the API
    call fails for any reason (network, missing key, bad response) so the
    endpoint never breaks the demo.
    """
    if not is_available():
        return template_story

    try:
        import anthropic  # imported lazily so the package is only required if this path is used

        client = anthropic.Anthropic()
        language_instruction = (
            "Write it in English." if lang == "en"
            else "Write it in simple, everyday Kannada (not formal/literary Kannada)."
        )
        prompt = f"""You are helping explain a detected social-engineering attack chain to a
non-technical potential victim. Here is the structured evidence a rule-based detector
produced - do not invent new facts, only rephrase/clarify what is given.

Chain of stages: {chain_result['chain']}
Max stage reached: {chain_result['max_stage']}
Per-message signals: {json.dumps(chain_result['per_message_stage'], indent=2)}

Write a short (4-6 sentence) plain-language "threat story" explaining what is happening
and why it is dangerous. {language_instruction} Return ONLY JSON with a single key
"narrative", nothing else."""

        resp = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")

        # Robustly pull out the JSON object even if the model wraps it in
        # ```json fences or adds a stray sentence around it - never trust an
        # LLM to return perfectly clean output on every call.
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return template_story
        parsed = json.loads(match.group(0))
        narrative = parsed.get("narrative")
        if not narrative:
            return template_story

        return {**template_story, "narrative": narrative, "ai_enhanced": True}
    except Exception:
        return template_story
