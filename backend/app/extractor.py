"""
extractor.py
Step 1-3 of the ScamChain pipeline:
  1. Extract important information from a raw message
  2. Identify suspicious signals
  3. Identify entities (sender, organizations, domains, URLs, requested
     actions, credentials requested)

Deliberately rule-based (regex + keyword lexicons) rather than a heavy NLP
model: it is fast, dependency-light, fully explainable (every signal traces
back to a concrete keyword/pattern match), and works with zero external API
calls, which matters for a live demo.

IMPORTANT (language note): these lexicons are English-keyword-based. Demo
scenario messages are written in English on purpose - that is what this
detector actually understands. The Kannada UI mode (see i18n.py) localizes
the PRESENTATION of results, not the underlying scam text being analyzed.
See README.md "Limitations" for why, and what a real Kannada-input
detector would additionally need.

One general lexicon covers every demo scenario (bank, UPI, fake customer
care, digital arrest, job offer, electricity, courier, loan, investment) -
new scenarios are added by writing realistic messages that this SAME
lexicon already recognizes (plus a few new entries below), never by adding
a scenario-specific code path. That is what makes ScamChain a general
attack-chain reconstructor rather than nine hardcoded detectors.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict
from urllib.parse import urlparse


# --------------------------------------------------------------------------
# Lexicons — each entry maps a signal_type to the cues that trigger it.
# Keeping these as plain lists makes it trivial to extend during the hackathon.
# --------------------------------------------------------------------------

IMPERSONATION_CUES = [
    r"\bfrom your bank\b", r"\bofficial\b", r"\bsupport team\b",
    r"\bcustomer (service|care)\b", r"\bthis is\s+\w+\s+(bank|support|security|team)\b",
    r"\bwe are from\b", r"\bi(?:'m| am) from\b", r"\bgovernment\b", r"\bincome tax\b",
    r"\brbi\b", r"\bcyber ?crime (cell|department)\b", r"\bcourier (service|company)\b",
    r"\bamazon\b", r"\bpaypal\b", r"\bmicrosoft\b", r"\bapple support\b",
    # added for the wider scenario set - still one shared lexicon, not per-scenario code
    r"\bdigital arrest\b", r"\btrai\b", r"\belectricity board\b", r"\belectricity department\b",
    r"\bhr (team|department)\b", r"\brecruiter\b", r"\bloan (has been |is )?approved\b",
    r"\binvestigating officer\b", r"\bsub-?inspector\b", r"\btrading platform\b",
    r"\binvestment (firm|advisor)\b", r"\bloan app\b", r"\bcyber cell\b",
]

URGENCY_CUES = [
    r"\burgent(ly)?\b", r"\bimmediately\b", r"\bright away\b", r"\bact now\b",
    r"\bwithin \d+ (minutes?|hours?)\b", r"\bsuspend(ed)?\b", r"\bblock(ed)?\b",
    r"\bexpire[sd]?\b", r"\blast (chance|warning)\b", r"\baccount (will be|has been) (locked|frozen|suspended)\b",
    r"\blimited time\b", r"\bfailure to (respond|act)\b", r"\bproblem with your account\b",
    r"\bunusual activity\b", r"\bverify to avoid\b", r"\brestrict(ed)?\b",
    # isolation / fear tactics (digital-arrest style) and scarcity tactics (job/loan/investment)
    r"\bpower will be disconnected\b", r"\belectricity will be disconnected\b", r"\bfinal notice\b",
    r"\bfir will be filed\b", r"\bwarrant (will be issued|against you)\b",
    r"\bdo not disconnect\b", r"\bstay on the (call|line)\b", r"\bdo not tell anyone\b",
    r"\blimited (slots|seats)\b", r"\bonly \d+ (seats|slots) left\b", r"\boffer expires\b",
]

REDIRECT_CUES = [
    r"\bclick (this|the|here)\b", r"\bclick here\b", r"\bfollow this link\b",
    r"\bvisit (this|the) (site|link|page)\b", r"\btap (this|the) link\b",
    r"\bdownload (this|the) (app|file|attachment)\b",
    r"\bverify your (account|identity|details)\b", r"\bconfirm your (details|identity)\b",
    r"\bjoin this (whatsapp )?group\b", r"\binstall this app\b", r"\bdownload the loan app\b",
    r"\bapprove the (payment |collect )?request\b", r"\bclick to accept\b",
]

# Credential-type NOUNS - the actual sensitive data an attacker wants.
# Kept separate from the verb phrases below so we can surface clean entity
# labels like "OTP" / "CVV" instead of raw regex matches. The label is a
# canonical English KEY - i18n.py maps each key to its Kannada display text.
CREDENTIAL_TERMS = [
    (r"\botp\b", "OTP"),
    (r"\bone[- ]time password\b", "OTP"),
    (r"\bpin\b", "PIN"),
    (r"\bcvv\b", "CVV"),
    (r"\bpassword\b", "Password"),
    (r"\bcard number\b", "Card number"),
    (r"\baccount number\b", "Account number"),
    (r"\bupi pin\b", "UPI PIN"),
    (r"\baadhaar\b", "Aadhaar number"),
    (r"\bsocial security\b", "Social Security number"),
]

# Verb/demand phrases that signal an extraction attempt even without (or
# alongside) an explicit credential noun in the same message.
EXTRACTION_ACTION_CUES = [
    r"\bsend money\b", r"\btransfer\b", r"\bshare your\b", r"\benter your\b",
    r"\bprovide your\b",
    r"\bregistration fee\b", r"\bprocessing fee\b", r"\bsecurity deposit\b", r"\bjoining fee\b",
    r"\bcollect request\b", r"\bpayment request\b",
]

EXTRACTION_CUES = [t[0] for t in CREDENTIAL_TERMS] + EXTRACTION_ACTION_CUES

GENERIC_GREETING_CUES = [
    r"\bdear (customer|user|sir/madam|valued customer)\b", r"^hi[,!.]?\s*$",
    r"\bdear\s*,", r"\bhello,\s*$", r"\bcongratulations\b", r"\bgreetings\b",
]

URL_REGEX = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9-]+\.(?:com|net|org|in|co|xyz|info|biz|ru|tk)\b[^\s]*)",
    re.IGNORECASE,
)

# a very rough "does this URL look suspicious" heuristic
SUSPICIOUS_URL_HINTS = [
    r"bit\.ly", r"tinyurl", r"goo\.gl", r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}",  # IP address
    r"-verify", r"secure-", r"login-", r"account-", r"\.xyz", r"\.tk", r"\.ru",
]

ORG_KEYWORDS = [
    "bank", "amazon", "paypal", "microsoft", "apple", "government",
    "income tax", "rbi", "courier", "cyber crime", "police", "support team",
    "electricity board", "electricity department", "hr team", "hr department",
    "recruiter", "trading platform", "investment firm", "loan app", "cyber cell",
    "sub-inspector", "trai", "customer care",
]


@dataclass
class ExtractedMessage:
    index: int
    raw_text: str
    signals: Dict[str, List[str]] = field(default_factory=dict)   # signal_type -> matched phrases
    urls: List[str] = field(default_factory=list)
    suspicious_urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    organizations: List[str] = field(default_factory=list)
    credentials_requested: List[str] = field(default_factory=list)  # canonical keys, e.g. ["OTP"]
    requested_actions: List[Dict] = field(default_factory=list)      # structured, e.g. [{"kind":"provide_credential","credential":"OTP"}]
    signal_score: Dict[str, int] = field(default_factory=dict)    # signal_type -> count


def _find_all(cues: List[str], text_lower: str) -> List[str]:
    hits = []
    for pattern in cues:
        for m in re.finditer(pattern, text_lower):
            hits.append(m.group(0))
    return hits


def _extract_domain(url: str) -> str:
    # Bare "example.com/path" (no scheme) fails urlparse's netloc detection,
    # so give it one just for parsing purposes.
    candidate = url if "://" in url else f"http://{url}"
    try:
        netloc = urlparse(candidate).netloc
    except ValueError:
        return url
    return netloc or url


def _derive_requested_actions(text_lower: str, em_signals: Dict[str, List[str]],
                               credentials: List[str], has_url: bool) -> List[Dict]:
    """
    Returns a list of small structured dicts (never pre-formatted English
    strings) so the presentation layer can render them in whichever
    language was requested. `kind` is a stable, language-independent code.
    """
    actions: List[Dict] = []

    if em_signals.get("redirect"):
        actions.append({"kind": "click_link"} if has_url else {"kind": "follow_instructions"})

    for cred in credentials:
        actions.append({"kind": "provide_credential", "credential": cred})

    if re.search(r"\b(collect request|approve the (payment )?request|payment request)\b", text_lower):
        actions.append({"kind": "approve_payment_request"})

    if re.search(r"\b(registration fee|processing fee|security deposit|joining fee)\b", text_lower):
        actions.append({"kind": "pay_fee"})

    if re.search(r"\b(send money|transfer)\b", text_lower) and not any(a["kind"] == "pay_fee" for a in actions):
        actions.append({"kind": "send_money"})

    # dedupe while preserving order (dicts aren't hashable, so key on a tuple)
    seen = set()
    deduped = []
    for a in actions:
        key = (a["kind"], a.get("credential"))
        if key not in seen:
            seen.add(key)
            deduped.append(a)
    return deduped


def extract_message(index: int, text: str) -> ExtractedMessage:
    text_lower = text.lower()
    em = ExtractedMessage(index=index, raw_text=text)

    signal_map = {
        "impersonation": _find_all(IMPERSONATION_CUES, text_lower),
        "urgency": _find_all(URGENCY_CUES, text_lower),
        "redirect": _find_all(REDIRECT_CUES, text_lower),
        "extraction": _find_all(EXTRACTION_CUES, text_lower),
        "generic_greeting": _find_all(GENERIC_GREETING_CUES, text_lower),
    }
    em.signals = {k: v for k, v in signal_map.items() if v}
    em.signal_score = {k: len(v) for k, v in em.signals.items()}

    # URLs + domains
    urls = URL_REGEX.findall(text)
    em.urls = list(dict.fromkeys(urls))
    em.suspicious_urls = [
        u for u in em.urls
        if any(re.search(h, u, re.IGNORECASE) for h in SUSPICIOUS_URL_HINTS)
    ]
    em.domains = list(dict.fromkeys(_extract_domain(u) for u in em.urls))

    # Organizations (very lightweight keyword spotting)
    em.organizations = [kw for kw in ORG_KEYWORDS if kw in text_lower]

    # Credential entities (normalized labels, deduped)
    creds = []
    for pattern, label in CREDENTIAL_TERMS:
        if re.search(pattern, text_lower):
            creds.append(label)
    em.credentials_requested = list(dict.fromkeys(creds))

    # Requested-action entities (structured, language-independent)
    em.requested_actions = _derive_requested_actions(text_lower, em.signals, em.credentials_requested, bool(em.urls))

    return em


def extract_all(messages: List[str]) -> List[ExtractedMessage]:
    return [extract_message(i, m) for i, m in enumerate(messages)]
