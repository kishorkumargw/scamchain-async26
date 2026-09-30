"""
chain_classifier.py
ScamChain relationship + attack-chain reasoning layer.

The classifier keeps two related concepts separate:
  1. per-message stage = the furthest stage evidenced by that message
  2. attack chain = the chronological progression of stages evidenced across
     the whole conversation

A small relationship engine is also built here. The same relationship data
is consumed by graph_builder.py, so the evidence graph is a visualization of
actual reasoning inputs rather than an independent decorative graph.
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

STAGE_SIGNAL_CATEGORY = {
    "TRUST_IMPERSONATION": "impersonation",
    "PRESSURE": "urgency",
    "REDIRECT": "redirect",
    "EXTRACTION": "extraction",
}


def _stage_index(stage: str) -> int:
    return STAGE_ORDER.index(stage)


def _observed_stages(em: ExtractedMessage, is_first: bool = False) -> List[str]:
    """Return every stage directly evidenced by this message, in ladder order."""
    observed: List[str] = []

    # CONTACT is a conversation-context stage, not a suspicious signal.
    # Treat the first supplied message as the contact point.
    if is_first:
        observed.append("CONTACT")

    if em.signals.get("impersonation") or em.organizations:
        observed.append("TRUST_IMPERSONATION")
    if em.signals.get("urgency"):
        observed.append("PRESSURE")
    if em.signals.get("redirect") or em.suspicious_urls:
        observed.append("REDIRECT")
    if em.signals.get("extraction"):
        observed.append("EXTRACTION")

    return observed


def classify_stage(em: ExtractedMessage) -> str:
    """Classify the furthest stage evidenced by one message."""
    observed = _observed_stages(em)
    return observed[-1] if observed else "CONTACT"


def _build_stage_evidence(extracted: List[ExtractedMessage], per_message: List[Dict]) -> Dict[str, List[Dict]]:
    evidence: Dict[str, List[Dict]] = {stage: [] for stage in STAGE_ORDER}

    for position, (em, pm) in enumerate(zip(extracted, per_message)):
        # Explicit signal-backed stages.
        for stage, category in STAGE_SIGNAL_CATEGORY.items():
            phrases = em.signals.get(category, [])
            if phrases:
                evidence[stage].append({"index": em.index, "phrases": phrases})

        # URL evidence can support REDIRECT even without an explicit click/follow phrase.
        if em.suspicious_urls and not any(e["index"] == em.index for e in evidence["REDIRECT"]):
            evidence["REDIRECT"].append({
                "index": em.index,
                "phrases": [f"suspicious link: {em.suspicious_urls[0]}"],
            })

        # CONTACT is the first message context. If it has a generic greeting,
        # use that concrete phrase; otherwise make the contextual basis explicit.
        if position == 0:
            greeting_phrases = em.signals.get("generic_greeting", [])
            evidence["CONTACT"].append({
                "index": em.index,
                "phrases": greeting_phrases if greeting_phrases else ["first message in the sequence"],
            })

    return evidence


def _relationship_for_pair(left: ExtractedMessage, right: ExtractedMessage,
                           left_pm: Dict, right_pm: Dict) -> Dict:
    """Explain why two adjacent messages belong to the same conversation path."""
    reasons: List[str] = ["messages occur consecutively in the supplied sequence"]
    evidence: List[str] = []
    relationship_types: List[str] = ["temporal"]

    left_orgs = set(left.organizations)
    right_orgs = set(right.organizations)
    shared_orgs = sorted(left_orgs & right_orgs)
    if shared_orgs:
        relationship_types.append("shared_organization")
        reasons.append("both messages reference the same organization")
        evidence.extend(shared_orgs)

    shared_domains = sorted(set(left.domains) & set(right.domains))
    if shared_domains:
        relationship_types.append("shared_domain")
        reasons.append("both messages reference the same domain")
        evidence.extend(shared_domains)

    shared_credentials = sorted(set(left.credentials_requested) & set(right.credentials_requested))
    if shared_credentials:
        relationship_types.append("shared_credential")
        reasons.append("both messages reference the same credential type")
        evidence.extend(shared_credentials)

    left_actions = {a.get("kind") for a in left.requested_actions}
    right_actions = {a.get("kind") for a in right.requested_actions}
    shared_actions = sorted(x for x in left_actions & right_actions if x)
    if shared_actions:
        relationship_types.append("shared_action")
        reasons.append("both messages request the same action type")
        evidence.extend(shared_actions)

    left_stage = left_pm["stage"]
    right_stage = right_pm["stage"]
    left_i = _stage_index(left_stage)
    right_i = _stage_index(right_stage)
    if right_i > left_i:
        relationship_types.append("stage_progression")
        reasons.append(f"stage progresses from {left_stage} to {right_stage}")
        evidence.append(f"{left_stage} → {right_stage}")
    elif right_i == left_i:
        relationship_types.append("same_stage")

    # A pair with semantic/entity overlap is stronger evidence of connection
    # than sequence alone. This is an explainability label, not a probability.
    strength = "strong" if len(relationship_types) >= 3 else "moderate"

    return {
        "source": left.index,
        "target": right.index,
        "relationship_types": relationship_types,
        "strength": strength,
        "reason": "; ".join(reasons),
        "evidence": list(dict.fromkeys(evidence)),
        "from_stage": left_stage,
        "to_stage": right_stage,
    }


def _build_relationships(extracted: List[ExtractedMessage], per_message: List[Dict]) -> List[Dict]:
    return [
        _relationship_for_pair(extracted[i], extracted[i + 1], per_message[i], per_message[i + 1])
        for i in range(len(extracted) - 1)
    ]


def _build_chain_from_evidence(extracted: List[ExtractedMessage], stage_evidence: Dict[str, List[Dict]]) -> List[str]:
    """
    Reconstruct a chronological stage chain from observed evidence.

    We never invent an intermediate stage merely because a later stage exists.
    A stage enters the chain only when at least one supplied message contains
    evidence for it. CONTACT is included as the first conversation context.
    """
    chain: List[str] = []
    if extracted:
        chain.append("CONTACT")

    # Track the furthest stage already represented in the chain. This prevents
    # later low-stage signals from making the aggregate chain regress.
    last_index = _stage_index("CONTACT") if chain else -1

    for em in extracted:
        observed = _observed_stages(em, is_first=(em.index == 0))
        for stage in observed:
            idx = _stage_index(stage)
            if idx > last_index and stage not in chain:
                chain.append(stage)
                last_index = idx

    # Do not claim CONTACT twice if the first message had no other evidence.
    return chain


def _build_chain_core(extracted: List[ExtractedMessage]) -> Dict:
    """Build the deterministic chain result without contribution analysis."""
    per_message = []
    for em in extracted:
        stage = classify_stage(em)
        reasons = []
        for _, phrases in em.signals.items():
            reasons.extend(phrases)
        if em.suspicious_urls:
            reasons.append(f"suspicious link: {em.suspicious_urls[0]}")
        per_message.append({
            "index": em.index,
            "stage": stage,
            "reasons": list(dict.fromkeys(reasons)),
            "raw_text": em.raw_text,
            "credentials_requested": em.credentials_requested,
            "requested_actions": em.requested_actions,
            "domains": em.domains,
            "url_evidence": em.url_evidence,
        })

    stage_evidence = _build_stage_evidence(extracted, per_message)
    relationships = _build_relationships(extracted, per_message)
    chain = _build_chain_from_evidence(extracted, stage_evidence)

    stage_indices = [_stage_index(pm["stage"]) for pm in per_message]
    max_idx = max(stage_indices) if stage_indices else 0
    max_stage = STAGE_ORDER[max_idx]

    is_escalating = (
        all(stage_indices[i] <= stage_indices[i + 1] for i in range(len(stage_indices) - 1))
        if len(stage_indices) > 1 else False
    )

    result = {
        "per_message_stage": per_message,
        "chain": chain,
        "max_stage": max_stage,
        "max_stage_index": max_idx,
        "is_escalating": is_escalating,
        "stage_evidence": stage_evidence,
        "relationships": relationships,
    }
    result["evidence_summary"] = _build_evidence_summary(extracted, result)
    return result


def _build_evidence_summary(extracted: List[ExtractedMessage], result: Dict) -> Dict:
    stages_supported = [s for s in STAGE_ORDER if result["stage_evidence"].get(s)]
    suspicious_urls = sum(len(em.suspicious_urls) for em in extracted)
    url_indicator_count = sum(len(u.get("indicators", [])) for em in extracted for u in em.url_evidence)
    credentials = sum(len(em.credentials_requested) for em in extracted)
    relationships = result.get("relationships", [])
    strong_relationships = sum(1 for r in relationships if r.get("strength") == "strong")
    signal_types = sorted({
        signal_type for em in extracted for signal_type in em.signals
        if signal_type != "generic_greeting"
    })
    total_signal_hits = sum(
        len(phrases) for em in extracted for signal_type, phrases in em.signals.items()
        if signal_type != "generic_greeting"
    )
    entities = {
        value
        for em in extracted
        for group in (em.organizations, em.urls, em.domains, em.credentials_requested)
        for value in group
    }
    entities.update(
        f"action:{a.get('kind')}:{a.get('credential','')}"
        for em in extracted for a in em.requested_actions
    )
    coverage = round((len(stages_supported) / len(STAGE_ORDER)) * 100) if STAGE_ORDER else 0
    return {
        "messages_analyzed": len(extracted),
        "messages_with_signals": sum(1 for em in extracted if any(k != "generic_greeting" for k in em.signals)),
        "signal_types_detected": signal_types,
        "signal_hit_count": total_signal_hits,
        "entities_observed": len(entities),
        "stages_supported": stages_supported,
        "stages_supported_count": len(stages_supported),
        "stages_total": len(STAGE_ORDER),
        "stage_evidence_coverage_percent": coverage,
        "relationship_count": len(relationships),
        "strong_relationship_count": strong_relationships,
        "suspicious_url_count": suspicious_urls,
        "url_indicator_count": url_indicator_count,
        "credential_request_count": credentials,
    }

def _build_message_contributions(extracted: List[ExtractedMessage], full_result: Dict) -> List[Dict]:
    """
    Measure each message's contribution by replaying the deterministic pipeline
    with that single message removed.

    This is deliberately framed as a model-based counterfactual, not a claim of
    real-world causality: "removing this message changes the reconstructed chain"
    under ScamChain's current evidence rules.
    """
    contributions: List[Dict] = []
    full_chain = full_result["chain"]
    full_max_stage = full_result["max_stage"]
    full_max_idx = full_result["max_stage_index"]

    for pos, em in enumerate(extracted):
        remaining = extracted[:pos] + extracted[pos + 1:]
        without_result = _build_chain_core(remaining)
        without_chain = without_result["chain"]
        without_stage = without_result["max_stage"]
        without_idx = without_result["max_stage_index"]

        introduced_stages = [stage for stage in full_chain if stage not in without_chain]
        stage_delta = full_max_idx - without_idx
        changes_max_stage = full_max_stage != without_stage
        is_turning_point = changes_max_stage and stage_delta > 0

        if is_turning_point:
            impact = "changes_reconstructed_max_stage"
        elif introduced_stages:
            impact = "supports_stage_in_chain"
        else:
            impact = "no_change_to_reconstructed_chain"

        contributions.append({
            "index": em.index,
            "message_number": pos + 1,
            "raw_text": em.raw_text,
            "stage_with_message": full_result["per_message_stage"][pos]["stage"] if pos < len(full_result["per_message_stage"]) else classify_stage(em),
            "full_chain": full_chain,
            "chain_without_message": without_chain,
            "max_stage_with_message": full_max_stage,
            "max_stage_without_message": without_stage,
            "stage_delta": stage_delta,
            "introduced_stages": introduced_stages,
            "impact": impact,
            "turning_point": is_turning_point,
            "evidence": full_result["per_message_stage"][pos]["reasons"] if pos < len(full_result["per_message_stage"]) else [],
        })

    return contributions


def build_chain(extracted: List[ExtractedMessage]) -> Dict:
    result = _build_chain_core(extracted)
    result["message_contributions"] = _build_message_contributions(extracted, result)
    return result