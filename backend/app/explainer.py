"""
explainer.py
Steps 8-9 of the pipeline: generate a human-readable explanation of the
attack chain, a plain risk rating, a per-stage evidence breakdown, and a
structured defensive response (What happened / Why it's risky / What to do).

Deliberately separates two different kinds of claim:
  - EVIDENCE  - concrete facts pulled straight out of the input (a phrase
    that matched, a URL that was flagged, a credential that was named).
  - INFERENCE - ScamChain's interpretation of what those facts add up to.
Judges (and real victims) deserve to know which is which.

All English/Kannada text comes from i18n.py - this module only assembles
WHICH structured facts to show; it never hardcodes display strings itself,
so adding a third language later means editing i18n.py, not this file.

Template-based by default (deterministic, always works, zero cost/latency -
important for a live demo). If ANTHROPIC_API_KEY is set, llm.py can
optionally re-narrate the SAME structured evidence more naturally, clearly
labeled as LLM-assisted interpretation layered on top of - never replacing -
this deterministic result (see llm.py and Feature 7 of the product brief).
"""

from typing import List, Dict
from . import i18n
from .chain_classifier import STAGE_ORDER

RISK_BY_STAGE = {
    "CONTACT": "LOW",
    "TRUST_IMPERSONATION": "LOW",
    "PRESSURE": "MEDIUM",
    "REDIRECT": "HIGH",
    "EXTRACTION": "HIGH",
}


def _build_evidence(chain_result: Dict, lang: str) -> List[str]:
    """Objective, concrete facts only - each line traces to a specific message."""
    lines = []
    for pm in chain_result["per_message_stage"]:
        n = pm["index"] + 1
        if pm["reasons"]:
            lines.append(f"[{n}] " + ", ".join(dict.fromkeys(pm["reasons"])))
        if pm.get("credentials_requested"):
            creds = [i18n.credential_label(lang, c) for c in pm["credentials_requested"]]
            lines.append(f"[{n}] " + ", ".join(creds))
        if pm.get("requested_actions"):
            actions = [i18n.render_action(lang, a) for a in pm["requested_actions"]]
            lines.append(f"[{n}] " + "; ".join(actions))
    return lines


def _build_inference(chain_result: Dict, lang: str) -> List[str]:
    """Interpretive claims, always hedged - never stated as confirmed fact."""
    chain = chain_result["chain"]
    max_stage = chain_result["max_stage"]

    if len(chain) <= 1 and max_stage in ("CONTACT", "TRUST_IMPERSONATION"):
        return [
            "Not enough signals have appeared yet to infer a specific attack pattern - this may simply be a low-signal or benign message."
            if lang == "en" else
            "ನಿರ್ದಿಷ್ಟ ದಾಳಿಯ ಮಾದರಿಯನ್ನು ಊಹಿಸಲು ಇನ್ನೂ ಸಾಕಷ್ಟು ಸೂಚನೆಗಳು ಕಂಡುಬಂದಿಲ್ಲ — ಇದು ಕೇವಲ ಕಡಿಮೆ-ಸೂಚನೆಯ ಅಥವಾ ನಿರುಪದ್ರವ ಸಂದೇಶವಾಗಿರಬಹುದು."
        ]

    if lang == "en":
        lines = ["This pattern is consistent with a phishing/vishing scam that impersonates a trusted organization to obtain credentials or money."]
        if chain_result["is_escalating"] and len(chain) >= 3:
            stage_words = " \u2192 ".join(i18n.stage_label(lang, s) for s in chain)
            lines.append(
                f"The signals escalate in a consistent order ({stage_words}) rather than appearing randomly, "
                "which suggests a scripted attack rather than a one-off suspicious message."
            )
        if max_stage in ("REDIRECT", "EXTRACTION"):
            lines.append(
                "The attacker appears to be attempting to move the target off a safe channel and toward directly "
                "surrendering credentials or funds - this is ScamChain's interpretation of the evidence above, not a confirmed fact."
            )
    else:
        lines = ["ಈ ಮಾದರಿ, ರುಜುವಾತು ಅಥವಾ ಹಣ ಪಡೆಯಲು ನಂಬಿಕಸ್ಥ ಸಂಸ್ಥೆಯಂತೆ ನಟಿಸುವ ಫಿಶಿಂಗ್/ವಿಶಿಂಗ್ ವಂಚನೆಯನ್ನು ಹೋಲುತ್ತದೆ."]
        if chain_result["is_escalating"] and len(chain) >= 3:
            stage_words = " \u2192 ".join(i18n.stage_label(lang, s) for s in chain)
            lines.append(
                f"ಸೂಚನೆಗಳು ಯಾದೃಚ್ಛಿಕವಾಗಿ ಅಲ್ಲದೆ ಒಂದು ಸ್ಥಿರ ಕ್ರಮದಲ್ಲಿ ({stage_words}) ಏರುತ್ತಿವೆ — "
                "ಇದು ಒಂದು ಬಾರಿಯ ಅನುಮಾನಾಸ್ಪದ ಸಂದೇಶಕ್ಕಿಂತ, ಸಿದ್ಧಪಡಿಸಿದ ದಾಳಿಯನ್ನು ಸೂಚಿಸುತ್ತದೆ."
            )
        if max_stage in ("REDIRECT", "EXTRACTION"):
            lines.append(
                "ಆಕ್ರಮಣಕಾರ ಬಲಿಪಶುವನ್ನು ಸುರಕ್ಷಿತ ಚಾನಲ್‌ನಿಂದ ಹೊರತಂದು ನೇರವಾಗಿ ರುಜುವಾತು ಅಥವಾ ಹಣ ನೀಡುವಂತೆ "
                "ಮಾಡಲು ಪ್ರಯತ್ನಿಸುತ್ತಿದ್ದಾರೆ — ಇದು ಮೇಲಿನ ಪುರಾವೆಗಳ ಆಧಾರದ ಮೇಲಿನ ScamChain ವ್ಯಾಖ್ಯಾನ, ಖಚಿತ ಸತ್ಯವಲ್ಲ."
            )
    return lines


def _build_stage_breakdown(chain_result: Dict, lang: str) -> List[Dict]:
    """Feature 2: for each stage actually reached, show evidence / why it
    matters / what the attacker is attempting - in stage (chain) order."""
    breakdown = []
    stage_evidence = chain_result["stage_evidence"]
    for stage in chain_result["chain"]:
        entries = stage_evidence.get(stage, [])
        evidence_phrases = []
        for e in entries:
            evidence_phrases.extend(e["phrases"])
        evidence_phrases = list(dict.fromkeys(evidence_phrases))
        breakdown.append({
            "stage": stage,
            "stage_label": i18n.stage_label(lang, stage),
            "evidence": evidence_phrases,
            "why_it_matters": i18n.why_it_matters(lang, stage),
            "attacker_goal": i18n.attacker_goal(lang, stage),
        })
    return breakdown


def _build_response(chain_result: Dict, risk_level: str, lang: str) -> Dict:
    """Feature 6: WHAT HAPPENED / WHY IT IS RISKY / WHAT TO DO NOW."""
    chain = chain_result["chain"]
    max_stage = chain_result["max_stage"]
    stage_words = " \u2192 ".join(i18n.stage_label(lang, s) for s in chain)

    if lang == "en":
        if len(chain) <= 1:
            what_happened = "Only a single, low-signal step was detected - no multi-stage progression yet."
        else:
            what_happened = f"The conversation progressed through: {stage_words} (ending at {i18n.stage_label(lang, max_stage)})."
    else:
        if len(chain) <= 1:
            what_happened = "ಕೇವಲ ಒಂದು, ಕಡಿಮೆ-ಸೂಚನೆಯ ಹೆಜ್ಜೆ ಮಾತ್ರ ಪತ್ತೆಯಾಗಿದೆ — ಇನ್ನೂ ಬಹು-ಹಂತದ ಪ್ರಗತಿ ಇಲ್ಲ."
        else:
            what_happened = f"ಸಂಭಾಷಣೆ ಈ ಹಂತಗಳ ಮೂಲಕ ಸಾಗಿದೆ: {stage_words} (ಅಂತಿಮವಾಗಿ {i18n.stage_label(lang, max_stage)} ತಲುಪಿದೆ)."

    what_to_do = i18n.recommendation(lang, max_stage) + [i18n.final_advice_line(lang)]

    return {
        "what_happened": what_happened,
        "why_risky": i18n.risk_reason(lang, max_stage),
        "what_to_do": what_to_do,
    }


def _build_timeline(chain_result: Dict, lang: str) -> List[Dict]:
    """Feature 3: per-message timeline (message N -> stage), separate from
    both the aggregate stage ladder and the evidence graph."""
    timeline = []
    for pm in chain_result["per_message_stage"]:
        text = pm["raw_text"]
        preview = text if len(text) <= 90 else text[:87].rstrip() + "..."
        evidence = list(dict.fromkeys(pm["reasons"]))
        if pm.get("credentials_requested"):
            evidence += [i18n.credential_label(lang, c) for c in pm["credentials_requested"]]
        if pm.get("requested_actions"):
            evidence += [i18n.render_action(lang, a) for a in pm["requested_actions"]]
        timeline.append({
            "index": pm["index"],
            "preview": preview,
            "stage": pm["stage"],
            "stage_label": i18n.stage_label(lang, pm["stage"]),
            "evidence": list(dict.fromkeys(evidence)),
        })
    return timeline


def build_threat_story(extracted, chain_result: Dict, lang: str = "en") -> Dict:
    lang = i18n.normalize_lang(lang)
    chain = chain_result["chain"]
    max_stage = chain_result["max_stage"]
    per_message = chain_result["per_message_stage"]

    if len(chain) <= 1 and max_stage == "CONTACT":
        narrative = (
            "This looks like an isolated, low-signal message. No escalating attack "
            "pattern detected yet - keep monitoring if more messages arrive."
        ) if lang == "en" else (
            "ಇದು ಪ್ರತ್ಯೇಕ, ಕಡಿಮೆ-ಸೂಚನೆಯ ಸಂದೇಶದಂತೆ ಕಾಣುತ್ತದೆ. ಇನ್ನೂ ಯಾವುದೇ ಏರುತ್ತಿರುವ ದಾಳಿಯ "
            "ಮಾದರಿ ಪತ್ತೆಯಾಗಿಲ್ಲ — ಹೆಚ್ಚಿನ ಸಂದೇಶಗಳು ಬಂದರೆ ಗಮನಿಸುತ್ತಿರಿ."
        )
    else:
        stage_words = " \u2192 ".join(chain)
        if lang == "en":
            lines = [f"ScamChain reconstructed a {len(chain)}-stage attack pattern across {len(per_message)} message(s): {stage_words}."]
            for stage in chain:
                lines.append(f"- {i18n.stage_label(lang, stage)}: {i18n.stage_description(lang, stage)}")
        else:
            lines = [f"ScamChain {len(per_message)} ಸಂದೇಶಗಳಲ್ಲಿ {len(chain)}-ಹಂತದ ದಾಳಿಯ ಮಾದರಿಯನ್ನು ಪುನರ್ನಿರ್ಮಿಸಿದೆ: {stage_words}."]
            for stage in chain:
                lines.append(f"- {i18n.stage_label(lang, stage)}: {i18n.stage_description(lang, stage)}")
        narrative = "\n".join(lines)

    verdict = "ATTACK CHAIN DETECTED" if len(chain) >= 3 or max_stage in ("REDIRECT", "EXTRACTION") else "LOW-CONFIDENCE / MONITOR"
    risk_level = RISK_BY_STAGE[max_stage]

    return {
        "lang": lang,
        "verdict": verdict,
        "verdict_label": i18n.verdict_label(lang, verdict),
        "narrative": narrative,
        "current_stage": max_stage,
        "current_stage_label": i18n.stage_label(lang, max_stage),
        "risk_level": risk_level,
        "risk_level_label": i18n.risk_level_label(lang, risk_level),
        "risk_reason": i18n.risk_reason(lang, max_stage),
        "evidence": _build_evidence(chain_result, lang),
        "inference": _build_inference(chain_result, lang),
        "recommendation": i18n.recommendation(lang, max_stage),
        "stage_breakdown": _build_stage_breakdown(chain_result, lang),
        "response": _build_response(chain_result, risk_level, lang),
        "timeline": _build_timeline(chain_result, lang),
    }
