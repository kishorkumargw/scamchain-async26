"""
graph_builder.py
Build the judge-facing evidence graph from ScamChain's extracted entities,
stage evidence, and relationship reasoning.

The graph contains both concrete evidence nodes and explicit stage nodes.
That makes the graph useful as an audit surface: a judge can trace
Message -> evidence -> stage and inspect why adjacent messages are connected.
"""

import networkx as nx
from typing import List, Dict, Optional
from .extractor import ExtractedMessage
from . import i18n

ATTACKER_NODE_ID = "attacker:sender"
ATTACKER_LABEL = {"en": "Sender (unverified)", "kn": "ಕಳುಹಿಸಿದವರು (ಪರಿಶೀಲಿಸದ)"}


def _action_node_key(action: Dict) -> str:
    if action["kind"] == "provide_credential":
        return f"action:provide_credential:{action.get('credential', '')}"
    return f"action:{action['kind']}"


def build_evidence_graph(extracted: List[ExtractedMessage], stages: List[Dict],
                         lang: str = "en", stage_evidence: Optional[Dict] = None,
                         relationships: Optional[List[Dict]] = None) -> Dict:
    lang = i18n.normalize_lang(lang)
    g = nx.DiGraph()
    stage_by_index = {s["index"]: s["stage"] for s in stages}
    stage_evidence = stage_evidence or {s: [] for s in [
        "CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"
    ]}
    relationships = relationships or []

    g.add_node(ATTACKER_NODE_ID, type="attacker", label=ATTACKER_LABEL[lang])

    for em in extracted:
        node_id = f"msg{em.index}"
        g.add_node(
            node_id,
            type="message",
            label=f"Message {em.index + 1}",
            stage=stage_by_index.get(em.index, "CONTACT"),
            text=em.raw_text,
        )
        g.add_edge(ATTACKER_NODE_ID, node_id, type="sent", label="sent")

    # Evidence-backed relationship edge between each adjacent pair.
    for rel in relationships:
        source = f"msg{rel['source']}"
        target = f"msg{rel['target']}"
        g.add_edge(
            source,
            target,
            type="relationship",
            label=rel["relationship_types"][0].replace("_", " "),
            relationship_types=rel["relationship_types"],
            strength=rel["strength"],
            reason=rel["reason"],
            evidence=rel["evidence"],
            from_stage=rel["from_stage"],
            to_stage=rel["to_stage"],
        )

    # Explicit stage nodes make the chain auditable inside the graph itself.
    for stage, entries in stage_evidence.items():
        if not entries:
            continue
        stage_id = f"stage:{stage}"
        g.add_node(
            stage_id,
            type="stage",
            stage=stage,
            label=i18n.stage_label(lang, stage),
            evidence_count=len(entries),
        )
        for entry in entries:
            msg_id = f"msg{entry['index']}"
            g.add_edge(
                msg_id,
                stage_id,
                type="supports_stage",
                label="supports",
                reason=f"Message {entry['index'] + 1} provides evidence for {i18n.stage_label(lang, stage)}",
                evidence=entry["phrases"],
                strength="strong",
            )

    for em in extracted:
        msg_id = f"msg{em.index}"

        for org in em.organizations:
            node_id = f"org:{org}"
            if node_id not in g:
                g.add_node(node_id, type="organization", label=i18n.org_label(lang, org))
            g.add_edge(
                msg_id, node_id, type="claims_to_be", label="claims",
                reason="message references this organization",
                evidence=[org], strength="strong",
            )
            g.add_edge(
                ATTACKER_NODE_ID, node_id, type="impersonates", label="impersonates",
                reason="sender presents itself as the referenced organization",
                evidence=[org], strength="strong",
            )

        url_evidence_by_url = {u.get("url"): u for u in em.url_evidence}
        for url in em.urls:
            node_id = f"url:{url}"
            suspicious = url in em.suspicious_urls
            url_info = url_evidence_by_url.get(url, {})
            indicators = url_info.get("indicators", [])
            if node_id not in g:
                g.add_node(
                    node_id,
                    type="url",
                    label=url,
                    suspicious=suspicious,
                    assessment=url_info.get("assessment", "no local suspicious indicators detected"),
                    indicators=indicators,
                )
            edge_evidence = [url] + indicators
            g.add_edge(
                msg_id, node_id, type="contains_link", label="contains link",
                reason=("message contains this URL; " + "; ".join(indicators) if indicators else "message contains this URL"),
                evidence=list(dict.fromkeys(edge_evidence)),
                strength="strong" if suspicious or indicators else "moderate",
            )

        for domain in em.domains:
            node_id = f"domain:{domain}"
            if node_id not in g:
                g.add_node(node_id, type="domain", label=domain)
            for url in em.urls:
                if f"url:{url}" in g and domain in url:
                    g.add_edge(
                        f"url:{url}", node_id, type="resolves_to", label="domain",
                        reason="domain extracted from URL",
                        evidence=[domain], strength="strong",
                    )

        for action in em.requested_actions:
            node_id = _action_node_key(action)
            if node_id not in g:
                g.add_node(node_id, type="requested_action", label=i18n.render_action(lang, action))
            g.add_edge(
                msg_id, node_id, type="requests", label="requests",
                reason="message requests this action",
                evidence=[i18n.render_action(lang, action)], strength="strong",
            )

        for cred in em.credentials_requested:
            node_id = f"credential:{cred}"
            if node_id not in g:
                g.add_node(node_id, type="credential", label=i18n.credential_label(lang, cred))
            g.add_edge(
                msg_id, node_id, type="requests", label="requests",
                reason="message requests a sensitive credential",
                evidence=[i18n.credential_label(lang, cred)], strength="strong",
            )

    nodes = [{"id": n, **data} for n, data in g.nodes(data=True)]
    edges = [{"id": f"edge:{i}", "source": u, "target": v, **data}
             for i, (u, v, data) in enumerate(g.edges(data=True))]

    return {"nodes": nodes, "edges": edges}
