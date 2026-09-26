"""
graph_builder.py
Step 5 of the pipeline: build the evidence graph connecting the sender,
messages/events, organizations claimed, URLs/domains, requested actions,
and credentials requested.

We use networkx purely as a convenient in-memory graph structure; the
output is serialized to plain node/edge lists so the frontend can render
it with vis.js without needing networkx on the client.

Node types: attacker, message, organization, url, domain, requested_action,
credential. Kept deliberately small in count (shared entities are deduped
into single nodes) so the graph stays readable rather than overcrowded -
see PIPELINE_FIXES.md for why that matters for a judge-facing demo.
"""

import networkx as nx
from typing import List, Dict
from .extractor import ExtractedMessage
from . import i18n

ATTACKER_NODE_ID = "attacker:sender"

ATTACKER_LABEL = {"en": "Sender (unverified)", "kn": "ಕಳುಹಿಸಿದವರು (ಪರಿಶೀಲಿಸದ)"}


def _action_node_key(action: Dict) -> str:
    # Stable, language-independent key so the same action from different
    # messages/languages collapses into one node instead of duplicating.
    if action["kind"] == "provide_credential":
        return f"action:provide_credential:{action.get('credential', '')}"
    return f"action:{action['kind']}"


def build_evidence_graph(extracted: List[ExtractedMessage], stages: List[Dict], lang: str = "en") -> Dict:
    lang = i18n.normalize_lang(lang)
    g = nx.DiGraph()
    stage_by_index = {s["index"]: s["stage"] for s in stages}

    # A single node represents "whoever sent these messages" - in this MVP
    # all input messages are treated as one conversation thread from one
    # sender, which matches the demo scenario (a single attacker impersonating
    # a bank/organization across several messages).
    g.add_node(ATTACKER_NODE_ID, type="attacker", label=ATTACKER_LABEL[lang])

    # message/event nodes, and the attacker -> message edge
    for em in extracted:
        node_id = f"msg{em.index}"
        g.add_node(
            node_id, type="message", label=f"Message {em.index + 1}",
            stage=stage_by_index.get(em.index, "CONTACT"), text=em.raw_text,
        )
        g.add_edge(ATTACKER_NODE_ID, node_id, type="sent")

    # temporal edges between consecutive messages
    for i in range(len(extracted) - 1):
        g.add_edge(f"msg{i}", f"msg{i+1}", type="leads_to",
                    label=f"{stage_by_index.get(i)} \u2192 {stage_by_index.get(i+1)}")

    for em in extracted:
        msg_id = f"msg{em.index}"

        for org in em.organizations:
            node_id = f"org:{org}"
            if node_id not in g:
                g.add_node(node_id, type="organization", label=i18n.org_label(lang, org))
            g.add_edge(msg_id, node_id, type="claims_to_be")
            # the attacker impersonating the org is the more meaningful edge
            # for the graph story than "message mentions org"
            g.add_edge(ATTACKER_NODE_ID, node_id, type="impersonates")

        for url in em.urls:
            node_id = f"url:{url}"
            suspicious = url in em.suspicious_urls
            if node_id not in g:
                g.add_node(node_id, type="url", label=url, suspicious=suspicious)
            g.add_edge(msg_id, node_id, type="contains_link")

        for domain in em.domains:
            node_id = f"domain:{domain}"
            if node_id not in g:
                g.add_node(node_id, type="domain", label=domain)
            for url in em.urls:
                if f"url:{url}" in g and domain in url:
                    g.add_edge(f"url:{url}", node_id, type="resolves_to")

        for action in em.requested_actions:
            node_id = _action_node_key(action)
            if node_id not in g:
                g.add_node(node_id, type="requested_action", label=i18n.render_action(lang, action))
            g.add_edge(msg_id, node_id, type="requests")

        for cred in em.credentials_requested:
            node_id = f"credential:{cred}"
            if node_id not in g:
                g.add_node(node_id, type="credential", label=i18n.credential_label(lang, cred))
            g.add_edge(msg_id, node_id, type="requests")

    nodes = [{"id": n, **data} for n, data in g.nodes(data=True)]
    edges = [{"source": u, "target": v, **data} for u, v, data in g.edges(data=True)]

    return {"nodes": nodes, "edges": edges}
