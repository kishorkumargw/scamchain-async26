/*
 * i18n.js
 * Static UI-chrome translations (headings, buttons, labels, error text).
 * This is separate from the backend's i18n.py on purpose: these strings
 * never depend on the analysis result, so translating them client-side
 * means the language toggle is instant (no network round trip) - the
 * ANALYSIS text (evidence, explanation, response) is what actually comes
 * from the backend already rendered in the chosen language, since that
 * text depends on what was detected, not just the UI chrome.
 *
 * Usage: elements tagged data-i18n="key" get their textContent replaced;
 * data-i18n-placeholder="key" sets the placeholder attribute instead.
 * Call applyStaticTranslations(lang) whenever the language changes.
 */

const STRINGS = {
  en: {
    brand_tag: "attack-chain reconstruction — MVP",
    tagline: "ScamChain does not simply classify a message. It reconstructs the attack behind multiple connected signals.",
    conn_checking: "checking backend…",
    conn_ok: "backend connected",
    conn_bad: "backend unreachable — start it with: uvicorn app.main:app --port 8000",
    recheck_btn: "recheck",
    scenario_label: "Choose a demo scenario",
    scenario_placeholder: "— select a scenario —",
    scenario_hint: "Every scenario runs through the exact same ScamChain pipeline - nothing is hardcoded per scenario.",
    input_heading: "Input",
    input_hint: "Paste in the raw signals - messages, email bodies, links - in the order they were received, or pick a demo scenario above. You can still edit anything before analyzing.",
    add_msg_btn: "+ add message",
    analyze_btn: "Analyze Attack",
    legend_heading: "Legend",
    step_signals: "Signals", step_evidence: "Evidence", step_relationships: "Relationships",
    step_chain: "Attack Chain", step_explanation: "Explanation", step_response: "Response",
    signals_heading: "Signals detected",
    signals_hint: "Every suspicious phrase found in each message - the raw material everything else is built from.",
    evidence_heading: "Evidence",
    evidence_hint: "Concrete entities pulled out of the signals above.",
    ev_orgs: "Organizations claimed", ev_urls: "URLs found",
    ev_actions: "Requested actions", ev_creds: "Credentials requested",
    stage_coverage: "Stage evidence coverage", signal_hits: "Signal matches", relationships_count: "Relationships", entities_observed: "Entities observed",
    url_evidence_heading: "URL evidence", no_url_indicators: "No local indicators",
    none_yet: "none detected",
    relationships_heading: "Relationships — evidence graph",
    relationships_hint: "How the sender, messages, entities and signals connect to each other.",
    chain_heading: "Attack chain",
    chain_hint: "Click a stage to see its supporting evidence.",
    timeline_heading: "Attack timeline",
    contribution_heading: "Message contribution",
    contribution_hint: "Remove one message at a time to see whether the reconstructed attack state changes.",
    turning_point: "Turning point",
    chain_unchanged: "Chain unchanged",
    message_label: "Message",
    message_supports: "This message supports",
    without_message: "Without message",
    full_chain_label: "Full reconstructed chain",
    without_chain_label: "Chain without this message",
    introduced_stages: "Stages introduced by this message",
    counterfactual_note: "Counterfactual check: this shows what ScamChain reconstructs when this message is removed; it is not a claim of real-world causality.",
    timeline_hint: "The same chain, message by message.",
    explanation_heading: "Explanation",
    explanation_hint: "For every stage reached: the evidence found, why it matters, and what the attacker is attempting.",
    why_it_matters: "Why it matters",
    attacker_goal: "Attacker is attempting to",
    evidence_label: "Evidence",
    inference_heading: "Overall interpretation (inference — not a confirmed fact)",
    response_heading: "Defensive response",
    what_happened: "What happened", why_risky: "Why it is risky", what_to_do: "What to do now",
    error_no_messages: "Add at least one message first, or pick a demo scenario.",
    could_not_analyze: "Could not analyze:",
    graph_error: "Graph rendering failed - the data is still fully analyzed, see the panels above/below.",
    progress_1: "Extracting signals…", progress_2: "Connecting evidence…", progress_3: "Reconstructing attack…",
    select_stage_hint: "Select a stage above to see its evidence.",
    selected_stage: "Selected stage",
    graph_detail_hint: "Click a relationship edge to inspect why the evidence is connected.",
    graph_relationship: "Relationship", graph_stage_support: "Stage support",
    graph_why_connected: "Why connected", graph_strength: "Strength", graph_evidence: "Evidence",
  },
  kn: {
    brand_tag: "ದಾಳಿ ಸರಪಳಿ ಪುನರ್ನಿರ್ಮಾಣ — MVP",
    tagline: "ScamChain ಒಂದು ಸಂದೇಶವನ್ನು ಕೇವಲ ವರ್ಗೀಕರಿಸುವುದಿಲ್ಲ. ಇದು ಹಲವು ಸಂಪರ್ಕಿತ ಸೂಚನೆಗಳ ಹಿಂದಿನ ದಾಳಿಯನ್ನು ಪುನರ್ನಿರ್ಮಿಸುತ್ತದೆ.",
    conn_checking: "ಬ್ಯಾಕೆಂಡ್ ಪರಿಶೀಲಿಸಲಾಗುತ್ತಿದೆ…",
    conn_ok: "ಬ್ಯಾಕೆಂಡ್ ಸಂಪರ್ಕಗೊಂಡಿದೆ",
    conn_bad: "ಬ್ಯಾಕೆಂಡ್ ತಲುಪಲಾಗುತ್ತಿಲ್ಲ — ಇದನ್ನು ಪ್ರಾರಂಭಿಸಿ: uvicorn app.main:app --port 8000",
    recheck_btn: "ಮರುಪರಿಶೀಲಿಸಿ",
    scenario_label: "ಡೆಮೊ ಸನ್ನಿವೇಶ ಆರಿಸಿ",
    scenario_placeholder: "— ಸನ್ನಿವೇಶ ಆರಿಸಿ —",
    scenario_hint: "ಪ್ರತಿ ಸನ್ನಿವೇಶವೂ ಒಂದೇ ScamChain ಪೈಪ್‌ಲೈನ್ ಮೂಲಕ ಹಾದುಹೋಗುತ್ತದೆ — ಯಾವುದೂ ಪ್ರತ್ಯೇಕವಾಗಿ ಹಾರ್ಡ್‌ಕೋಡ್ ಆಗಿಲ್ಲ.",
    input_heading: "ಇನ್‌ಪುಟ್",
    input_hint: "ಸಂದೇಶಗಳು, ಇಮೇಲ್, ಲಿಂಕ್‌ಗಳನ್ನು ಬಂದ ಕ್ರಮದಲ್ಲಿ ಅಂಟಿಸಿ, ಅಥವಾ ಮೇಲಿನ ಡೆಮೊ ಸನ್ನಿವೇಶ ಆರಿಸಿ. ವಿಶ್ಲೇಷಿಸುವ ಮೊದಲು ಯಾವುದನ್ನಾದರೂ ಸಂಪಾದಿಸಬಹುದು.",
    add_msg_btn: "+ ಸಂದೇಶ ಸೇರಿಸಿ",
    analyze_btn: "ದಾಳಿ ವಿಶ್ಲೇಷಿಸಿ",
    legend_heading: "ಸಂಕೇತಗಳ ವಿವರಣೆ",
    step_signals: "ಸೂಚನೆಗಳು", step_evidence: "ಪುರಾವೆ", step_relationships: "ಸಂಬಂಧಗಳು",
    step_chain: "ದಾಳಿ ಸರಪಳಿ", step_explanation: "ವಿವರಣೆ", step_response: "ಪ್ರತಿಕ್ರಿಯೆ",
    signals_heading: "ಪತ್ತೆಯಾದ ಸೂಚನೆಗಳು",
    signals_hint: "ಪ್ರತಿ ಸಂದೇಶದಲ್ಲಿ ಕಂಡುಬಂದ ಅನುಮಾನಾಸ್ಪದ ಪದಗುಚ್ಛಗಳು.",
    evidence_heading: "ಪುರಾವೆ",
    evidence_hint: "ಮೇಲಿನ ಸೂಚನೆಗಳಿಂದ ಹೊರತೆಗೆದ ನಿಖರ ಘಟಕಗಳು.",
    ev_orgs: "ಹೇಳಿಕೊಂಡ ಸಂಸ್ಥೆಗಳು", ev_urls: "ಸಿಕ್ಕ URL ಗಳು",
    ev_actions: "ಕೇಳಿದ ಕ್ರಮಗಳು", ev_creds: "ಕೇಳಿದ ರುಜುವಾತುಗಳು",
    stage_coverage: "ಹಂತ ಪುರಾವೆ ವ್ಯಾಪ್ತಿ", signal_hits: "ಸೂಚನೆ ಹೊಂದಿಕೆಗಳು", relationships_count: "ಸಂಬಂಧಗಳು", entities_observed: "ಗಮನಿಸಿದ ಘಟಕಗಳು",
    url_evidence_heading: "URL ಪುರಾವೆ", no_url_indicators: "ಸ್ಥಳೀಯ ಸೂಚನೆಗಳಿಲ್ಲ",
    none_yet: "ಯಾವುದೂ ಪತ್ತೆಯಾಗಿಲ್ಲ",
    relationships_heading: "ಸಂಬಂಧಗಳು — ಪುರಾವೆ ಗ್ರಾಫ್",
    relationships_hint: "ಕಳುಹಿಸಿದವರು, ಸಂದೇಶಗಳು, ಘಟಕಗಳು ಮತ್ತು ಸೂಚನೆಗಳು ಹೇಗೆ ಸಂಪರ್ಕಗೊಂಡಿವೆ.",
    chain_heading: "ದಾಳಿ ಸರಪಳಿ",
    chain_hint: "ಪುರಾವೆ ನೋಡಲು ಒಂದು ಹಂತವನ್ನು ಕ್ಲಿಕ್ ಮಾಡಿ.",
    timeline_heading: "ದಾಳಿ ಟೈಮ್‌ಲೈನ್",
    contribution_heading: "ಸಂದೇಶದ ಕೊಡುಗೆ",
    contribution_hint: "ಒಂದೊಂದು ಸಂದೇಶವನ್ನು ತೆಗೆದುಹಾಕಿ, ಪುನರ್ನಿರ್ಮಿಸಿದ ದಾಳಿ ಸ್ಥಿತಿ ಬದಲಾಗುತ್ತದೆಯೇ ನೋಡಿ.",
    turning_point: "ತಿರುವು ಬಿಂದು",
    chain_unchanged: "ಸರಪಳಿ ಬದಲಾಗಿಲ್ಲ",
    message_label: "ಸಂದೇಶ",
    message_supports: "ಈ ಸಂದೇಶ ಬೆಂಬಲಿಸುವ ಹಂತ",
    without_message: "ಸಂದೇಶವಿಲ್ಲದೆ",
    full_chain_label: "ಪೂರ್ಣ ಪುನರ್ನಿರ್ಮಿಸಿದ ಸರಪಳಿ",
    without_chain_label: "ಈ ಸಂದೇಶವಿಲ್ಲದ ಸರಪಳಿ",
    introduced_stages: "ಈ ಸಂದೇಶ ಪರಿಚಯಿಸಿದ ಹಂತಗಳು",
    counterfactual_note: "ಪರ್ಯಾಯ ಪರಿಶೀಲನೆ: ಈ ಸಂದೇಶವನ್ನು ತೆಗೆದುಹಾಕಿದಾಗ ScamChain ಏನು ಪುನರ್ನಿರ್ಮಿಸುತ್ತದೆ ಎಂಬುದನ್ನು ಇದು ತೋರಿಸುತ್ತದೆ; ಇದು ವಾಸ್ತವ ಜಗತ್ತಿನ ಕಾರಣ-ಪರಿಣಾಮದ ಹೇಳಿಕೆ ಅಲ್ಲ.",
    timeline_hint: "ಅದೇ ಸರಪಳಿ, ಸಂದೇಶ-ಸಂದೇಶವಾಗಿ.",
    explanation_heading: "ವಿವರಣೆ",
    explanation_hint: "ತಲುಪಿದ ಪ್ರತಿ ಹಂತಕ್ಕೂ: ಸಿಕ್ಕ ಪುರಾವೆ, ಇದು ಏಕೆ ಮುಖ್ಯ, ಮತ್ತು ಆಕ್ರಮಣಕಾರ ಏನು ಪ್ರಯತ್ನಿಸುತ್ತಿದ್ದಾರೆ.",
    why_it_matters: "ಇದು ಏಕೆ ಮುಖ್ಯ",
    attacker_goal: "ಆಕ್ರಮಣಕಾರ ಪ್ರಯತ್ನಿಸುತ್ತಿರುವುದು",
    evidence_label: "ಪುರಾವೆ",
    inference_heading: "ಒಟ್ಟಾರೆ ವ್ಯಾಖ್ಯಾನ (ಊಹೆ — ಖಚಿತ ಸತ್ಯವಲ್ಲ)",
    response_heading: "ರಕ್ಷಣಾ ಪ್ರತಿಕ್ರಿಯೆ",
    what_happened: "ಏನಾಯಿತು", why_risky: "ಇದು ಏಕೆ ಅಪಾಯಕಾರಿ", what_to_do: "ಈಗ ಏನು ಮಾಡಬೇಕು",
    error_no_messages: "ಮೊದಲು ಕನಿಷ್ಠ ಒಂದು ಸಂದೇಶ ಸೇರಿಸಿ, ಅಥವಾ ಡೆಮೊ ಸನ್ನಿವೇಶ ಆರಿಸಿ.",
    could_not_analyze: "ವಿಶ್ಲೇಷಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ:",
    graph_error: "ಗ್ರಾಫ್ ರೆಂಡರಿಂಗ್ ವಿಫಲವಾಗಿದೆ - ಡೇಟಾ ಇನ್ನೂ ಸಂಪೂರ್ಣವಾಗಿ ವಿಶ್ಲೇಷಿಸಲಾಗಿದೆ, ಮೇಲೆ/ಕೆಳಗಿನ ಫಲಕಗಳನ್ನು ನೋಡಿ.",
    progress_1: "ಸೂಚನೆಗಳನ್ನು ಹೊರತೆಗೆಯಲಾಗುತ್ತಿದೆ…", progress_2: "ಪುರಾವೆಗಳನ್ನು ಸಂಪರ್ಕಿಸಲಾಗುತ್ತಿದೆ…", progress_3: "ದಾಳಿಯನ್ನು ಪುನರ್ನಿರ್ಮಿಸಲಾಗುತ್ತಿದೆ…",
    select_stage_hint: "ಪುರಾವೆ ನೋಡಲು ಮೇಲೆ ಒಂದು ಹಂತವನ್ನು ಆರಿಸಿ.",
    selected_stage: "ಆಯ್ಕೆ ಮಾಡಿದ ಹಂತ",
    graph_detail_hint: "ಪುರಾವೆಗಳು ಏಕೆ ಸಂಪರ್ಕಗೊಂಡಿವೆ ಎಂಬುದನ್ನು ನೋಡಲು ಸಂಬಂಧದ ಅಂಚನ್ನು ಕ್ಲಿಕ್ ಮಾಡಿ.",
    graph_relationship: "ಸಂಬಂಧ", graph_stage_support: "ಹಂತದ ಪುರಾವೆ",
    graph_why_connected: "ಏಕೆ ಸಂಪರ್ಕಗೊಂಡಿದೆ", graph_strength: "ಬಲ", graph_evidence: "ಪುರಾವೆ",
  },
};

let currentLang = "en";

function t(key) {
  return (STRINGS[currentLang] && STRINGS[currentLang][key]) || STRINGS.en[key] || key;
}

function applyStaticTranslations(lang) {
  currentLang = STRINGS[lang] ? lang : "en";
  document.querySelectorAll("[data-i18n]").forEach(el => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
    el.setAttribute("placeholder", t(el.getAttribute("data-i18n-placeholder")));
  });
  document.documentElement.lang = currentLang === "kn" ? "kn" : "en";
}
