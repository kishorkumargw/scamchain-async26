"""
chain_classifier.py
Steps 4, 6, 7 of the pipeline: connect related information, determine the
attack stage of each message, and reconstruct the overall attack chain.

Stage priority (highest wins when a message triggers several signal types):
    EXTRACTION > REDIRECT > PRESSURE(urgency) > TRUST/IMPERSONATION > CONTACT
This mirrors how a real attack escalates — a message that both pressures
AND asks for an OTP is, for the victim's safety, best classified at the
more dangerous (later) stage it has reached.
"""

from typing import List, Dict
from .extractor import ExtractedMessage

STAGE_ORDER = ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"]

STAGE_DESCRIPTIONS = {
    "CONTACT": "Initial contact is made with the target, often with a generic greeting and no immediate ask.",
    "TRUST_IMPERSONATION": "The sender claims a trusted identity (a bank, company, or authority) to build credibility.",
    "PRESSURE": "Urgency or fear is introduced to short-circuit careful thinking (account suspension, deadlines, threats).",
    "REDIRECT": "The victim is pushed toward an external link or app, moving them off a safe channel.",
    "EXTRACTION": "The attacker requests sensitive data (OTP, password, card details) or a money transfer — the payoff stage.",
}

# Which raw signal category (from extractor.py) evidences which canonical
# stage. Used to build stage_evidence: a message can contribute evidence to
# a stage even if it was ultimately *classified* at a later, more dangerous
# stage (see classify_stage's priority order) - so clicking "PRESSURE" in the
# UI still shows the message that raised urgency, even if that same message
# also happened to contain a link and got classified as REDIRECT overall.
STAGE_SIGNAL_CATEGORY = {
    "TRUST_IMPERSONATION": "impersonation",
    "PRESSURE": "urgency",
    "REDIRECT": "redirect",
    "EXTRACTION": "extraction",
}


def classify_stage(em: ExtractedMessage) -> str:
    if em.signals.get("extraction"):
        return "EXTRACTION"
    if em.signals.get("redirect") or em.suspicious_urls:
        return "REDIRECT"
    if em.signals.get("urgency"):
        return "PRESSURE"
    if em.signals.get("impersonation") or em.organizations:
        return "TRUST_IMPERSONATION"
    return "CONTACT"


def build_chain(extracted: List[ExtractedMessage]) -> Dict:
    """
    Returns:
      {
        "per_message_stage": [{"index":0, "stage":"CONTACT", "reasons": [...],
                                "credentials_requested": [...], "requested_actions": [...],
                                "domains": [...]}, ...],
        "chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
        "max_stage": "EXTRACTION",
        "max_stage_index": 4,
        "is_escalating": True,
        "stage_evidence": {"CONTACT": [{"index":0, "phrases":[...]}], ...}
      }
    """
    per_message = []
    for em in extracted:
        stage = classify_stage(em)
        reasons = []
        for sig_type, phrases in em.signals.items():
            reasons.extend(phrases)
        if em.suspicious_urls:
            reasons.append(f"suspicious link: {em.suspicious_urls[0]}")
        per_message.append({
            "index": em.index,
            "stage": stage,
            "reasons": reasons,
            "raw_text": em.raw_text,
            "credentials_requested": em.credentials_requested,
            "requested_actions": em.requested_actions,
            "domains": em.domains,
        })

    # Build the deduplicated ordered chain (consecutive repeats collapsed)
    chain = []
    for pm in per_message:
        if not chain or chain[-1] != pm["stage"]:
            chain.append(pm["stage"])

    stage_indices = [STAGE_ORDER.index(pm["stage"]) for pm in per_message]
    max_idx = max(stage_indices) if stage_indices else 0
    max_stage = STAGE_ORDER[max_idx]

    # "Escalating" = stage indices are non-decreasing overall (a real attack
    # chain climbs the ladder rather than jumping around randomly)
    is_escalating = all(
        stage_indices[i] <= stage_indices[i + 1] for i in range(len(stage_indices) - 1)
    ) if len(stage_indices) > 1 else False

    stage_evidence = _build_stage_evidence(extracted, per_message)

    return {
        "per_message_stage": per_message,
        "chain": chain,
        "max_stage": max_stage,
        "max_stage_index": max_idx,
        "is_escalating": is_escalating,
        "stage_evidence": stage_evidence,
    }


def _build_stage_evidence(extracted: List[ExtractedMessage], per_message: List[Dict]) -> Dict[str, List[Dict]]:
    evidence: Dict[str, List[Dict]] = {stage: [] for stage in STAGE_ORDER}

    for em, pm in zip(extracted, per_message):
        for stage, category in STAGE_SIGNAL_CATEGORY.items():
            phrases = em.signals.get(category, [])
            if phrases:
                evidence[stage].append({"index": em.index, "phrases": phrases})
        # REDIRECT also gets credit for a suspicious URL even without an
        # explicit "click this" phrase (e.g. a bare link pasted in).
        if em.suspicious_urls and not any(e["index"] == em.index for e in evidence["REDIRECT"]):
            evidence["REDIRECT"].append({"index": em.index, "phrases": [f"suspicious link: {em.suspicious_urls[0]}"]})

    # CONTACT is the implicit "nothing else fired yet" stage - always give it
    # at least the first message, factually (not an assumption: it IS the
    # first message in the sequence).
    if per_message:
        first = per_message[0]
        greeting_phrases = extracted[0].signals.get("generic_greeting", [])
        evidence["CONTACT"].append({
            "index": 0,
            "phrases": greeting_phrases if greeting_phrases else ["first message in the sequence"],
        })

    return evidence
