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

LANGUAGE NOTE: the detector supports English plus a focused Kannada fraud lexicon
for common bank/account social-engineering cues. The Kannada coverage is intentionally
small and explainable rather than pretending to be full Kannada NLP. The original
message is always preserved as evidence, and mixed Kannada-English messages can still
trigger the shared signal families.

One general lexicon covers every demo scenario (bank, UPI, fake customer
care, digital arrest, job offer, electricity, courier, loan, investment) -
new scenarios are added by writing realistic messages that this SAME
lexicon already recognizes (plus a few new entries below), never by adding
a scenario-specific code path. That is what makes ScamChain a general
attack-chain reconstructor rather than nine hardcoded detectors.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict
from urllib.parse import urlparse


# --------------------------------------------------------------------------
# Lexicons — each entry maps a signal_type to the cues that trigger it.
# Keeping these as plain lists makes it trivial to extend during the hackathon.
# --------------------------------------------------------------------------

IMPERSONATION_CUES = [
    r"\bfrom your bank\b", r"\bsupport team\b",
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
    # Generic click wording is only treated as a redirect when it is tied to
    # a security/account/link/payment context. This prevents benign phrases
    # such as "click the company portal to view the agenda" from becoming a
    # suspicious redirect signal.
    r"\bclick\b.{0,45}\b(?:link|verify|verification|login|signin|sign-in|account|identity|details|payment|refund|security)\b",
    r"\b(?:link|verify|verification|login|signin|sign-in|account|identity|details|payment|refund|security)\b.{0,45}\bclick\b",
    r"\bfollow this link\b",
    r"\bvisit (this|the) (site|link|page)\b", r"\btap (this|the) link\b",
    r"\bdownload (this|the) (app|file|attachment)\b",
    r"\bverify your (account|identity|details)\b", r"\bconfirm your (details|identity)\b",
    r"\bjoin this (whatsapp )?group\b", r"\binstall this app\b", r"\bdownload the loan app\b",
    r"\bapprove the (payment |collect )?request\b", r"\bclick to accept\b",
]

# Mixed-language patterns where English words are embedded in Kannada text.
MIXED_LANGUAGE_REDIRECT_CUES = [
    r"\blink\b.{0,20}\bclick\b",
    r"\bclick\b.{0,20}\blink\b",
]


# --------------------------------------------------------------------------
# Focused Kannada cues for common social-engineering / bank fraud language.
# These are deliberately phrase-based and auditable: each match can be shown
# as evidence in the same graph/stage pipeline as English cues.
# --------------------------------------------------------------------------

KANNADA_IMPERSONATION_CUES = [
    r"ಬ್ಯಾಂಕ್[‌‍\s-]*(?:ನಿಂದ|ಅಧಿಕಾರಿ|ಸಿಬ್ಬಂದಿ|ಕಸ್ಟಮರ್|ಗ್ರಾಹಕ)",
    r"(?:ನಿಮ್ಮ\s*)?(?:ಬ್ಯಾಂಕ್|ಖಾತೆ|ಗ್ರಾಹಕ ಸೇವೆ)[^\n]{0,25}(?:ನಾವು|ನಾನು|ಅಧಿಕಾರಿ|ಸಿಬ್ಬಂದಿ)",
    r"ಗ್ರಾಹಕ\s*ಸೇವೆ",
    r"ಬ್ಯಾಂಕ್\s*ಅಧಿಕಾರಿ",
    r"ಸೈಬರ್\s*ಕ್ರೈಂ",
    r"ಪೊಲೀಸ್",
    r"ಆದಾಯ ತೆರಿಗೆ",
    r"ಆರ್\.?ಬಿ\.?ಐ",
    r"ಕೂರಿಯರ್",
    r"ವಿದ್ಯುತ್\s*(?:ಇಲಾಖೆ|ಮಂಡಳಿ)",
]

KANNADA_URGENCY_CUES = [
    r"ತಕ್ಷಣ", r"ತುರ್ತು", r"ಈಗಲೇ", r"ಇಂದು",
    r"ಖಾತೆ[^\n]{0,20}(?:ನಿಲ್ಲಿಸಲಾಗುತ್ತದೆ|ಮುಚ್ಚಲಾಗುತ್ತದೆ|ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ|ಬ್ಲಾಕ್)",
    r"ಖಾತೆ[^\n]{0,20}(?:ಅಮಾನತು|ನಿಷ್ಕ್ರಿಯ)",
    r"೨೪\s*ಗಂಟೆ", r"24\s*ಗಂಟೆ",
    r"ಕೊನೆಯ\s*(?:ಎಚ್ಚರಿಕೆ|ಅವಕಾಶ)",
    r"ದಂಡ", r"ಕ್ರಮ\s*ಕೈಗೊಳ್ಳಲಾಗುತ್ತದೆ",
]

KANNADA_REDIRECT_CUES = [
    r"ಲಿಂಕ್\s*(?:ಮೇಲೆ|ಕೆಳಗೆ)?\s*ಕ್ಲಿಕ್\s*ಮಾಡಿ",
    r"ಇಲ್ಲಿ\s*ಕ್ಲಿಕ್\s*ಮಾಡಿ",
    r"ಲಿಂಕ್\s*ತೆರೆಯಿರಿ",
    r"ವೆಬ್\s*(?:ಸೈಟ್|ಪುಟ)\s*ತೆರೆಯಿರಿ",
    r"ಆ್ಯಪ್\s*ಡೌನ್\s*ಲೋಡ್\s*ಮಾಡಿ",
    r"ಪರಿಶೀಲನೆ\s*ಗಾಗಿ\s*ಲಿಂಕ್",
    r"ಖಾತೆ\s*(?:ಪರಿಶೀಲಿಸಿ|ಪರಿಶೀಲನೆ\s*ಮಾಡಿ)",
    r"ವಿವರಗಳನ್ನು\s*ಪರಿಶೀಲಿಸಿ",
]

KANNADA_CREDENTIAL_TERMS = [
    (r"ಒಟಿಪಿ", "OTP"),
    (r"ಒ\.?\s*ಟಿ\.?\s*ಪಿ", "OTP"),
    (r"ಒನ್[-\s]*ಟೈಮ್\s*ಪಾಸ್?ವರ್ಡ್", "OTP"),
    (r"ಪಿನ್", "PIN"),
    (r"ಸಿವಿವಿ|ಸಿ\.?ವಿ\.?ವಿ", "CVV"),
    (r"ಪಾಸ್?ವರ್ಡ್", "Password"),
    (r"ಕಾರ್ಡ್\s*(?:ಸಂಖ್ಯೆ|ನಂಬರ್)", "Card number"),
    (r"ಖಾತೆ\s*(?:ಸಂಖ್ಯೆ|ನಂಬರ್)", "Account number"),
    (r"ಯುಪಿಐ\s*ಪಿನ್|ಯು\.?ಪಿ\.?ಐ\s*ಪಿನ್", "UPI PIN"),
]

KANNADA_EXTRACTION_ACTION_CUES = [
    r"ಒಟಿಪಿ[^\n]{0,20}(?:ನೀಡಿ|ಹೇಳಿ|ನಮೂದಿಸಿ)",
    r"ಪಿನ್[^\n]{0,20}(?:ನೀಡಿ|ಹೇಳಿ|ನಮೂದಿಸಿ)",
    r"ಪಾಸ್?ವರ್ಡ್[^\n]{0,20}(?:ನೀಡಿ|ಹೇಳಿ|ನಮೂದಿಸಿ)",
    r"ಕಾರ್ಡ್[^\n]{0,20}(?:ಸಂಖ್ಯೆ|ನಂಬರ್)[^\n]{0,20}(?:ನೀಡಿ|ಹೇಳಿ|ನಮೂದಿಸಿ)",
    r"ಹಣ\s*(?:ಕಳುಹಿಸಿ|ವರ್ಗಾಯಿಸಿ)",
    r"ಪಾವತಿ\s*(?:ಮಾಡಿ|ಕಳುಹಿಸಿ)",
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

CREDENTIAL_TERMS_ALL = CREDENTIAL_TERMS + KANNADA_CREDENTIAL_TERMS

# Verb/demand phrases that signal an extraction attempt even without (or
# alongside) an explicit credential noun in the same message.
EXTRACTION_ACTION_CUES = [
    r"\bsend money\b", r"\btransfer\b", r"\bshare your\b", r"\benter your\b",
    r"\bprovide your\b",
    r"\bregistration fee\b", r"\bprocessing fee\b", r"\bsecurity deposit\b", r"\bjoining fee\b",
    r"\bcollect request\b", r"\bpayment request\b",
]

EXTRACTION_CUES = [t[0] for t in CREDENTIAL_TERMS_ALL] + EXTRACTION_ACTION_CUES + KANNADA_EXTRACTION_ACTION_CUES

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
    url_evidence: List[Dict] = field(default_factory=list)        # per-URL explainable indicators


def _normalize_for_matching(text: str) -> str:
    """Normalize common scam-message obfuscation for rule matching only.

    The original message is preserved in ``raw_text``. This matching form
    handles Unicode variants, case, repeated whitespace/punctuation, and
    common spacing/punctuation tricks such as ``O.T.P`` or ``O T P`` without
    requiring an external NLP service.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = normalized.casefold()

    # Targeted canonicalization of common security terms. We intentionally
    # avoid global leetspeak conversion because that can create false matches
    # in ordinary prose.
    patterns = {
        r"\bo[\s._-]*t[\s._-]*p\b": "otp",
        r"\bp[\s._-]*i[\s._-]*n\b": "pin",
        r"\bc[\s._-]*v[\s._-]*v\b": "cvv",
        r"\bu[\s._-]*p[\s._-]*i[\s._-]*p[\s._-]*i[\s._-]*n\b": "upi pin",
        r"\bp[\s._-]*a[\s._-]*s[\s._-]*s[\s._-]*w[\s._-]*o[\s._-]*r[\s._-]*d\b": "password",
        r"\bc[\s._-]*l[\s._-]*i[\s._-]*c[\s._-]*k\b": "click",
        r"\bv[\s._-]*e[\s._-]*r[\s._-]*i[\s._-]*f[\s._-]*y\b": "verify",
        r"\be[\s._-]*n[\s._-]*t[\s._-]*e[\s._-]*r\b": "enter",
        r"\bp[\s._-]*r[\s._-]*o[\s._-]*v[\s._-]*i[\s._-]*d[\s._-]*e\b": "provide",
    }
    for pattern, replacement in patterns.items():
        normalized = re.sub(pattern, replacement, normalized)

    # Replace punctuation with spaces while preserving Unicode combining marks
    # used by Kannada and other Indic scripts. A broad ``[^\w]`` filter
    # would destroy vowel signs and make Kannada words impossible to match.
    normalized = "".join(" " if unicodedata.category(ch).startswith("P") else ch for ch in normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


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

    if re.search(r"(?:ಹಣ\s*(?:ಕಳುಹಿಸಿ|ವರ್ಗಾಯಿಸಿ)|ಪಾವತಿ\s*(?:ಮಾಡಿ|ಕಳುಹಿಸಿ))", text_lower):
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


URL_EVIDENCE_RULES = [
    ("shortener", re.compile(r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl)", re.IGNORECASE), "URL shortener"),
    ("ip_address", re.compile(r"^(?:https?://)?(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/|$)", re.IGNORECASE), "IP address used as destination"),
    ("unusual_tld", re.compile(r"\.(?:xyz|tk|ru|info|biz)(?:$|/)", re.IGNORECASE), "Unusual or high-risk TLD"),
    ("verification_wording", re.compile(r"(?:verify|verification|login|signin|sign-in|account|secure|security)", re.IGNORECASE), "Verification/login wording in URL"),
    ("http_only", re.compile(r"^http://", re.IGNORECASE), "URL does not use HTTPS"),
    ("brand_like_path", re.compile(r"(?:bank|upi|payment|support|refund|kyc|customer-care|customer_support)", re.IGNORECASE), "Brand/service wording in URL path"),
]

def _analyze_url(url: str, suspicious: bool) -> Dict:
    indicators = []
    codes = []
    for code, pattern, label in URL_EVIDENCE_RULES:
        if pattern.search(url):
            codes.append(code)
            indicators.append(label)
    return {
        "url": url,
        "indicators": indicators,
        "indicator_codes": codes,
        "assessment": "suspicious indicators detected" if suspicious or indicators else "no local suspicious indicators detected",
    }

def extract_message(index: int, text: str) -> ExtractedMessage:
    text_lower = _normalize_for_matching(text)
    em = ExtractedMessage(index=index, raw_text=text)

    signal_map = {
        "impersonation": _find_all(IMPERSONATION_CUES, text_lower) + _find_all(KANNADA_IMPERSONATION_CUES, text_lower),
        "urgency": _find_all(URGENCY_CUES, text_lower) + _find_all(KANNADA_URGENCY_CUES, text_lower),
        "redirect": (
            _find_all(REDIRECT_CUES, text_lower)
            + _find_all(KANNADA_REDIRECT_CUES, text_lower)
            + _find_all(MIXED_LANGUAGE_REDIRECT_CUES, text_lower)
        ),
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
    em.url_evidence = [_analyze_url(u, u in em.suspicious_urls) for u in em.urls]
    em.domains = list(dict.fromkeys(_extract_domain(u) for u in em.urls))

    # Organizations (very lightweight keyword spotting). Scan message text
    # rather than URLs/domains so a hostname such as secure-bankverify.xyz does
    # not itself become evidence that the sender is a legitimate/trusted bank.
    message_text_for_orgs = URL_REGEX.sub(" ", text_lower)
    org_hits = [kw for kw in ORG_KEYWORDS if kw in message_text_for_orgs]
    for kw in ["ಬ್ಯಾಂಕ್", "ಗ್ರಾಹಕ ಸೇವೆ", "ಸೈಬರ್ ಕ್ರೈಂ", "ಪೊಲೀಸ್", "ವಿದ್ಯುತ್ ಇಲಾಖೆ", "ಆದಾಯ ತೆರಿಗೆ", "ಕೂರಿಯರ್"]:
        if kw in message_text_for_orgs:
            org_hits.append(kw)
    em.organizations = list(dict.fromkeys(org_hits))

    # Credential entities (normalized labels, deduped)
    creds = []
    for pattern, label in CREDENTIAL_TERMS_ALL:
        if re.search(pattern, text_lower):
            creds.append(label)
    em.credentials_requested = list(dict.fromkeys(creds))

    # Requested-action entities (structured, language-independent)
    em.requested_actions = _derive_requested_actions(text_lower, em.signals, em.credentials_requested, bool(em.urls))

    return em


def extract_all(messages: List[str]) -> List[ExtractedMessage]:
    return [extract_message(i, m) for i, m in enumerate(messages)]
