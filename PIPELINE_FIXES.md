# ScamChain — QA / Hardening Pass

Full review of the MVP before hackathon submission: every item below was
actually reproduced (not just inspected) and then verified fixed — see the
"how it was verified" notes. Organized by the checklist used for the review.

## 1. Verified & fixed

**API errors / broken input handling**
- `POST /analyze` with `{"messages": []}` used to return `200 OK` with a
  nonsensical "isolated, low-signal message" narrative instead of an error.
  Fixed: empty (or all-blank) input now returns `400` with a clear
  `detail` message. Verified with curl against a clean venv install.
- Blank/whitespace-only entries mixed in with real messages used to flow
  through as fake "Message N" nodes in the evidence graph. Fixed: a
  pydantic validator on `AnalyzeRequest.messages` strips and drops blanks
  before the pipeline ever sees them.
- Any unexpected exception in the pipeline used to surface as a raw
  traceback / generic FastAPI 500. Fixed: the whole pipeline call is now
  wrapped, logs the real error server-side, and returns a clean
  `500 {"detail": "Analysis failed unexpectedly..."}` instead.

**AI response parsing / environment variables**
- `llm.py`'s optional Claude-narration hook was calling a model id
  an external narrative prototype was evaluated during development; it is not part of the final offline build.
  proxy, not the public Messages API a standalone script hits with a real
  an optional external narrative integration was explored during development; it is not part of the final offline submission.
- JSON parsing of the model's reply used `str.removeprefix/removesuffix`
  chained fence-stripping, which breaks if the model adds any commentary
  around the JSON. Fixed to a regex extraction of the `{...}` object, so
  it survives extra text/whitespace around the JSON.
- Confirmed (via `inspect.signature`) that the `messages.create(...)` call
  shape was tested during development; the external integration is removed from the final submission.
  the installed SDK version.

**Missing / mismatched dependencies**
- `requirements.txt` had hand-guessed version pins that were never actually
  installed or tested. Re-pinned to the exact versions verified by a fresh
  `python3 -m venv` + `pip install -r requirements.txt` + full pipeline run
  (fastapi 0.141.1, uvicorn 0.53.0, networkx 3.6.1, pydantic 2.13.5,
  external AI SDK is not included in the final requirements.

**Graph visualization / offline demo risk**
- The frontend loaded `vis-network` from a CDN (unpkg). At a venue with bad
  wifi, the whole graph panel would silently break. Fixed: the library is
  now vendored locally at `frontend/vendor/vis-network.min.js` (pulled via
  `npm pack`), with the CDN kept only as an automatic fallback
  (`onerror=...`) if that file is ever removed.
- A failure in graph rendering used to be caught by the same `try/catch` as
  the network request, so it could make a *successful* analysis look like
  a *failed* one. Fixed: graph rendering now has its own try/catch and
  failure state (`#graphError`), and never hides the verdict/story/table
  results.

**Loading / error / connection states**
- Added a persistent connection indicator (dot + status text) that pings
  `GET /health` on load and on demand ("recheck" button), so a
  disconnected backend is obvious before the presenter even hits Analyze.
- Added an editable API base URL field (was hardcoded), so the same page
  can point at `localhost` during dev and a deployed URL on demo day
  without editing source.
- The Analyze button now disables itself and shows a spinner while a
  request is in flight (previously nothing stopped a double-click from
  firing two overlapping requests).
- Fetch failures now surface the backend's actual error `detail` (e.g. the
  400 message above) instead of a generic "could not reach backend" for
  every kind of failure.

**Verification method**
- Backend: fresh-venv install + direct `curl` calls covering the happy
  path, empty input, blank input, and malformed JSON.
- Frontend: a real headless-Chromium run (Playwright) driving the actual
  page against the actual backend — loaded the bank-OTP example, clicked
  Analyze, and asserted on the rendered verdict/graph canvas/table/ladder
  text, then repeated with the backend intentionally unreachable to check
  the error path, then repeated with the courier-scam example. Zero
  uncaught JS errors in any run.

## 2. Not changed (already fine)
- FastAPI's built-in validation already correctly returns `422` for
  malformed JSON bodies and missing required fields — no fix needed there.
- The rule-based extraction/classification logic (stage priorities,
  chain-building, graph structure) was already producing the exact
  5-stage escalation from the pitch on the bank/OTP example and generalized
  correctly to the courier-scam example — left untouched.

## 3. Feature pass: i18n, 9 scenarios, timeline, per-stage breakdown

Extended (never rebuilt) the existing codebase. The Bank OTP demo's chain
output is byte-for-byte the same as before this pass (`TRUST_IMPERSONATION
→ PRESSURE → REDIRECT → EXTRACTION`) — verified by direct comparison, not
just re-reading the code.

**What changed, by file:**
- `extractor.py` — lexicons extended for 9 scenarios (UPI, digital-arrest,
  job/loan/investment/electricity vocabulary); `requested_actions` changed
  from pre-formatted English strings to structured `{"kind":...}` dicts so
  they can be rendered in either language; added domain extraction.
- `i18n.py` (new) — the EN/KN presentation layer: stage labels/
  descriptions, risk reasoning, recommendations, credential/org/action
  labels. Nothing outside this file (and the thin calls into it from
  `explainer.py`/`graph_builder.py`) branches on language — one backend,
  not two.
- `chain_classifier.py` — added `stage_evidence` (which messages support
  which stage, independent of that message's own final classification) so
  the UI can make each ladder stage clickable.
- `graph_builder.py` — added `attacker` (sender), `domain`,
  `requested_action`, and `credential` node types; all labels localized via
  `i18n.py`; kept node counts small (8-14 nodes across all 9 scenarios) so
  the graph stays readable.
- `explainer.py` — added risk level (LOW/MEDIUM/HIGH, no invented
  percentages), per-stage breakdown (evidence / why it matters / attacker's
  goal), the What-happened/Why-risky/What-to-do response block, and a
  timeline structure — all localized.
- `llm.py` — narrowed so the optional AI overlay only ever rewrites the
  `narrative` field; risk/recommendation/stage breakdown stay deterministic
  always (Feature 7: LLM-assisted interpretation must stay clearly separate
  from, and never replace, the rule-based decision logic).
- `scenarios.py` (new) — single registry of all 9 scenarios (bank OTP,
  UPI payment, fake customer care, digital arrest, fake job, electricity,
  courier, fake loan, investment). Every one is fictional content written
  to be recognized by the *same* shared lexicon — no per-scenario code path.
- `models.py` / `main.py` — added `lang` (with fallback-to-English for
  unsupported values); the final request schema intentionally has no external AI/API flag.
  schema extended with the new localized/structured fields; added
  `GET /languages` and `GET /scenarios`.
- `frontend/index.html` — full rewrite: language toggle (instant, no
  reload), scenario dropdown wired to `GET /scenarios`, clickable attack
  chain (shows per-stage evidence), a new Attack Timeline panel alongside
  the existing evidence graph (not a replacement), per-stage explanation
  cards, and the restructured Defensive Response block.
- `frontend/i18n.js` (new) — static UI-chrome translations, applied
  client-side so the language toggle never needs a network round trip for
  labels/buttons/errors.

**Verification method**
- All 9 scenarios run through `extract_all` → `build_chain` directly
  (no server) to confirm each produces a coherent, escalating multi-stage
  chain before touching the API layer at all.
- All 9 scenarios re-run through `build_evidence_graph` +
  `build_threat_story` in both languages with assertions on structure
  (timeline length, stage_breakdown length, node types) — all passed.
- All 9 scenarios re-run a third time over real HTTP (`urllib`, not just
  in-process) in both languages against a fresh-venv server.
- A real headless-Chromium (Playwright) session: loaded the page, selected
  each of the 9 scenarios from the dropdown, clicked Analyze, and asserted
  on rendered verdict/risk/stage-cards/timeline-items/graph-canvas for
  every one — zero uncaught JS errors across the whole run.
- Separately verified: clicking a ladder stage renders its evidence;
  switching English → Kannada mid-result triggers an automatic re-analysis
  of the same messages (not just a relabel) and both the verdict and the
  tagline render correctly in Kannada; pointing the UI at a dead backend
  URL still shows the existing clear error message and re-enables the
  Analyze button.

**Known limitations of this pass** (see README.md §12 for the full list):
scenario message content is English-only (the lexicons are English
keywords); organization/entity extraction is keyword-spotting, not real
NER; the graph assumes a single sender per conversation thread.
