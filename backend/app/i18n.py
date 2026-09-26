"""
i18n.py
The presentation layer: turns the language-independent, structured analysis
result (stage codes, canonical entity keys, structured action dicts) into
either English or Kannada display text.

Architecture (per product brief):
    User input -> ScamChain analysis (language-independent) -> structured
    result -> English/Kannada presentation layer (this module)

Nothing in extractor.py / chain_classifier.py / graph_builder.py branches on
language. Only this module, and the small amount of code in explainer.py /
main.py that calls into it, is language-aware - there is exactly one
backend, not a parallel Kannada one.

The Kannada strings here are deliberately plain, everyday Kannada (not
formal/literary), per the product brief. English technical terms that are
commonly used as-is in spoken Kannada (OTP, PIN, CVV, bank-app names) are
kept in Latin script rather than forced into an artificial Kannada
transliteration, which would read as unnatural to a real Kannada speaker.
"""

from typing import Dict, List

SUPPORTED_LANGS = {"en", "kn"}
DEFAULT_LANG = "en"


def normalize_lang(lang: str) -> str:
    """Feature 9 requirement: unsupported language -> fall back to English."""
    if lang in SUPPORTED_LANGS:
        return lang
    return DEFAULT_LANG


STAGE_LABEL = {
    "en": {
        "CONTACT": "Contact",
        "TRUST_IMPERSONATION": "Trust / Impersonation",
        "PRESSURE": "Pressure",
        "REDIRECT": "Redirect",
        "EXTRACTION": "Extraction",
    },
    "kn": {
        "CONTACT": "ಸಂಪರ್ಕ",
        "TRUST_IMPERSONATION": "ನಂಬಿಕೆ / ಸೋಗು",
        "PRESSURE": "ಒತ್ತಡ",
        "REDIRECT": "ಮರುನಿರ್ದೇಶನ",
        "EXTRACTION": "ಮಾಹಿತಿ ಕದಿಯುವಿಕೆ",
    },
}

STAGE_DESCRIPTION = {
    "en": {
        "CONTACT": "Initial contact is made with the target, often with a generic greeting and no immediate ask.",
        "TRUST_IMPERSONATION": "The sender claims a trusted identity (a bank, company, or authority) to build credibility.",
        "PRESSURE": "Urgency or fear is introduced to short-circuit careful thinking (account suspension, deadlines, threats).",
        "REDIRECT": "The victim is pushed toward an external link or app, moving them off a safe channel.",
        "EXTRACTION": "The attacker requests sensitive data (OTP, password, card details) or a money transfer - the payoff stage.",
    },
    "kn": {
        "CONTACT": "ಗುರಿಯೊಂದಿಗೆ ಮೊದಲ ಸಂಪರ್ಕ ಸಾಧಿಸಲಾಗುತ್ತದೆ, ಸಾಮಾನ್ಯವಾಗಿ ಸಾಮಾನ್ಯ ಶುಭಾಶಯದೊಂದಿಗೆ, ಯಾವುದೇ ತಕ್ಷಣದ ಬೇಡಿಕೆ ಇಲ್ಲದೆ.",
        "TRUST_IMPERSONATION": "ಕಳುಹಿಸುವವರು ನಂಬಿಕಸ್ಥ ಸಂಸ್ಥೆಯಂತೆ (ಬ್ಯಾಂಕ್, ಕಂಪನಿ, ಅಥವಾ ಅಧಿಕಾರಿ) ಹೇಳಿಕೊಂಡು ವಿಶ್ವಾಸ ಗಳಿಸಲು ಪ್ರಯತ್ನಿಸುತ್ತಾರೆ.",
        "PRESSURE": "ತ್ವರಿತ ಕ್ರಮಕ್ಕಾಗಿ ತುರ್ತು ಅಥವಾ ಭಯದ ಭಾಷೆ ಬಳಸಲಾಗುತ್ತದೆ (ಖಾತೆ ಸ್ಥಗಿತ, ಗಡುವು, ಬೆದರಿಕೆ).",
        "REDIRECT": "ಬಲಿಪಶುವನ್ನು ಸುರಕ್ಷಿತ ಚಾನಲ್‌ನಿಂದ ಹೊರಗಿನ ಲಿಂಕ್ ಅಥವಾ ಆ್ಯಪ್‌ಗೆ ತಳ್ಳಲಾಗುತ್ತದೆ.",
        "EXTRACTION": "ಆಕ್ರಮಣಕಾರ ಸೂಕ್ಷ್ಮ ಮಾಹಿತಿ (OTP, ಪಾಸ್‌ವರ್ಡ್, ಕಾರ್ಡ್ ವಿವರ) ಅಥವಾ ಹಣ ಕೇಳುತ್ತಾರೆ — ಇದೇ ಅಂತಿಮ ಹಂತ.",
    },
}

WHY_IT_MATTERS = {
    "en": {
        "CONTACT": "Establishing contact is the first step of nearly every social-engineering attack - on its own it isn't dangerous, but it sets up everything that follows.",
        "TRUST_IMPERSONATION": "Claiming a trusted identity makes the target more likely to comply with later requests without double-checking.",
        "PRESSURE": "Urgency and fear reduce the time a target spends verifying independently - exactly what an attacker wants.",
        "REDIRECT": "Moving the target to an external link/app takes them off a channel they can trust and onto one the attacker controls.",
        "EXTRACTION": "This is the payoff stage - once credentials, OTPs, or money are handed over, the attacker has what they came for.",
    },
    "kn": {
        "CONTACT": "ಸಂಪರ್ಕ ಸ್ಥಾಪಿಸುವುದು ಬಹುತೇಕ ಎಲ್ಲಾ ಸಾಮಾಜಿಕ ಎಂಜಿನಿಯರಿಂಗ್ ದಾಳಿಗಳ ಮೊದಲ ಹೆಜ್ಜೆ — ಇದೊಂದೇ ಅಪಾಯಕಾರಿ ಅಲ್ಲ, ಆದರೆ ಮುಂದಿನ ಎಲ್ಲದಕ್ಕೂ ಅಡಿಪಾಯ ಹಾಕುತ್ತದೆ.",
        "TRUST_IMPERSONATION": "ನಂಬಿಕಸ್ಥ ಗುರುತನ್ನು ಹೇಳಿಕೊಳ್ಳುವುದರಿಂದ, ಬಲಿಪಶು ಮರುಪರಿಶೀಲಿಸದೆ ಮುಂದಿನ ಬೇಡಿಕೆಗಳಿಗೆ ಒಪ್ಪುವ ಸಾಧ್ಯತೆ ಹೆಚ್ಚಾಗುತ್ತದೆ.",
        "PRESSURE": "ತುರ್ತು ಮತ್ತು ಭಯ, ಬಲಿಪಶು ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಲು ತೆಗೆದುಕೊಳ್ಳುವ ಸಮಯವನ್ನು ಕಡಿಮೆ ಮಾಡುತ್ತದೆ — ಇದೇ ಆಕ್ರಮಣಕಾರನಿಗೆ ಬೇಕಾಗಿರುವುದು.",
        "REDIRECT": "ಬಲಿಪಶುವನ್ನು ಬಾಹ್ಯ ಲಿಂಕ್/ಆ್ಯಪ್‌ಗೆ ಸ್ಥಳಾಂತರಿಸುವುದರಿಂದ, ಅವರು ನಂಬಬಹುದಾದ ಚಾನಲ್‌ನಿಂದ ಹೊರಬಂದು ಆಕ್ರಮಣಕಾರ ನಿಯಂತ್ರಿಸುವ ಚಾನಲ್‌ಗೆ ಹೋಗುತ್ತಾರೆ.",
        "EXTRACTION": "ಇದು ಅಂತಿಮ ಫಲಿತಾಂಶದ ಹಂತ — ಒಮ್ಮೆ ರುಜುವಾತು, OTP, ಅಥವಾ ಹಣ ನೀಡಿದ ನಂತರ ಆಕ್ರಮಣಕಾರನಿಗೆ ಬೇಕಾಗಿದ್ದು ಸಿಗುತ್ತದೆ.",
    },
}

ATTACKER_GOAL = {
    "en": {
        "CONTACT": "Open a communication channel with the target.",
        "TRUST_IMPERSONATION": "Get the target to believe they are dealing with a legitimate, authoritative source.",
        "PRESSURE": "Push the target into acting quickly, before they can verify or think it through.",
        "REDIRECT": "Move the target onto a channel or page the attacker controls.",
        "EXTRACTION": "Obtain credentials, OTPs, or a direct money transfer.",
    },
    "kn": {
        "CONTACT": "ಗುರಿಯೊಂದಿಗೆ ಸಂವಹನ ಚಾನಲ್ ತೆರೆಯುವುದು.",
        "TRUST_IMPERSONATION": "ತಾವು ನಿಜವಾದ, ಅಧಿಕೃತ ಮೂಲದೊಂದಿಗೆ ವ್ಯವಹರಿಸುತ್ತಿದ್ದಾರೆ ಎಂದು ಗುರಿಗೆ ನಂಬಿಸುವುದು.",
        "PRESSURE": "ಪರಿಶೀಲಿಸುವ ಅಥವಾ ಯೋಚಿಸುವ ಮೊದಲೇ ಗುರಿ ತ್ವರಿತವಾಗಿ ಕ್ರಮ ತೆಗೆದುಕೊಳ್ಳುವಂತೆ ಮಾಡುವುದು.",
        "REDIRECT": "ಗುರಿಯನ್ನು ಆಕ್ರಮಣಕಾರ ನಿಯಂತ್ರಿಸುವ ಚಾನಲ್ ಅಥವಾ ಪುಟಕ್ಕೆ ಸ್ಥಳಾಂತರಿಸುವುದು.",
        "EXTRACTION": "ರುಜುವಾತು, OTP, ಅಥವಾ ನೇರ ಹಣ ವರ್ಗಾವಣೆ ಪಡೆಯುವುದು.",
    },
}

RISK_LEVEL_LABEL = {
    "en": {"LOW": "LOW RISK", "MEDIUM": "MEDIUM RISK", "HIGH": "HIGH RISK"},
    "kn": {"LOW": "ಕಡಿಮೆ ಅಪಾಯ", "MEDIUM": "ಮಧ್ಯಮ ಅಪಾಯ", "HIGH": "ಹೆಚ್ಚಿನ ಅಪಾಯ"},
}

RISK_REASON_BY_STAGE = {
    "en": {
        "CONTACT": "Only initial contact was detected. Nothing suspicious enough to escalate yet - keep watching if more messages arrive.",
        "TRUST_IMPERSONATION": "An identity was claimed, but no pressure, link, or data request has appeared yet.",
        "PRESSURE": "Urgency/fear language was used to push for quick action. No link or data request yet, but this is a common setup step.",
        "REDIRECT": "The conversation pushed the target toward an external link, moving them off a safe channel - highly characteristic of phishing.",
        "EXTRACTION": "The conversation explicitly requested sensitive credentials or funds - the final, most damaging stage of a social-engineering attack.",
    },
    "kn": {
        "CONTACT": "ಇಲ್ಲಿಯವರೆಗೆ ಕೇವಲ ಆರಂಭಿಕ ಸಂಪರ್ಕ ಮಾತ್ರ ಪತ್ತೆಯಾಗಿದೆ. ಹೆಚ್ಚಿನ ಸಂದೇಶಗಳು ಬಂದರೆ ಗಮನಿಸುತ್ತಿರಿ.",
        "TRUST_IMPERSONATION": "ಒಂದು ಗುರುತನ್ನು ಹೇಳಿಕೊಳ್ಳಲಾಗಿದೆ, ಆದರೆ ಇನ್ನೂ ಒತ್ತಡ, ಲಿಂಕ್ ಅಥವಾ ಮಾಹಿತಿ ಬೇಡಿಕೆ ಕಂಡುಬಂದಿಲ್ಲ.",
        "PRESSURE": "ತ್ವರಿತ ಕ್ರಮಕ್ಕಾಗಿ ತುರ್ತು/ಭಯದ ಭಾಷೆ ಬಳಸಲಾಗಿದೆ. ಇನ್ನೂ ಲಿಂಕ್ ಅಥವಾ ಮಾಹಿತಿ ಬೇಡಿಕೆ ಇಲ್ಲ, ಆದರೆ ಇದು ಸಾಮಾನ್ಯ ಮೊದಲ ಹೆಜ್ಜೆ.",
        "REDIRECT": "ಸಂಭಾಷಣೆ ಬಳಕೆದಾರರನ್ನು ಸುರಕ್ಷಿತ ಚಾನಲ್‌ನಿಂದ ಹೊರಗಿನ ಲಿಂಕ್‌ಗೆ ತಳ್ಳಿದೆ — ಇದು ಫಿಶಿಂಗ್‌ನ ಸಾಮಾನ್ಯ ಲಕ್ಷಣ.",
        "EXTRACTION": "ಸಂಭಾಷಣೆ ಸ್ಪಷ್ಟವಾಗಿ ಸೂಕ್ಷ್ಮ ಮಾಹಿತಿ ಅಥವಾ ಹಣವನ್ನು ಕೇಳಿದೆ — ಇದು ಸಾಮಾಜಿಕ ಎಂಜಿನಿಯರಿಂಗ್ ದಾಳಿಯ ಅಂತಿಮ, ಅತ್ಯಂತ ಅಪಾಯಕಾರಿ ಹಂತ.",
    },
}

RECOMMENDATION_BY_STAGE = {
    "en": {
        "CONTACT": [
            "No sensitive action is needed yet - but treat unsolicited contact claiming to be your bank with caution.",
            "Do not assume the sender is who they claim to be, based on a greeting alone.",
        ],
        "TRUST_IMPERSONATION": [
            "Do not trust the claimed identity on its own.",
            "Verify independently using a number from the official website or the back of your card - not one given in the message.",
        ],
        "PRESSURE": [
            "Slow down - legitimate organizations do not threaten immediate account suspension over chat/SMS/email.",
            "Do not act on the stated deadline. Verify independently before doing anything.",
        ],
        "REDIRECT": [
            "Do not click the suspicious link.",
            "Do not provide credentials or OTPs.",
            "Verify the communication through an independent, trusted bank channel.",
            "Report the suspicious communication through the appropriate channel.",
        ],
        "EXTRACTION": [
            "Do not click the suspicious link.",
            "Do not provide credentials or OTPs.",
            "Verify the communication through an independent, trusted bank channel.",
            "Report the suspicious communication through the appropriate channel.",
        ],
    },
    "kn": {
        "CONTACT": [
            "ಇನ್ನೂ ಯಾವುದೇ ಸೂಕ್ಷ್ಮ ಕ್ರಮ ಅಗತ್ಯವಿಲ್ಲ — ಆದರೆ ಬ್ಯಾಂಕ್ ಎಂದು ಹೇಳಿಕೊಳ್ಳುವ ಅನಪೇಕ್ಷಿತ ಸಂಪರ್ಕದ ಬಗ್ಗೆ ಎಚ್ಚರವಹಿಸಿ.",
            "ಕೇವಲ ಶುಭಾಶಯದ ಆಧಾರದ ಮೇಲೆ ಕಳುಹಿಸುವವರು ಹೇಳಿಕೊಂಡಂತೆ ಇದ್ದಾರೆ ಎಂದು ಭಾವಿಸಬೇಡಿ.",
        ],
        "TRUST_IMPERSONATION": [
            "ಹೇಳಿಕೊಂಡ ಗುರುತನ್ನು ಮಾತ್ರ ನಂಬಬೇಡಿ.",
            "ಸಂದೇಶದಲ್ಲಿ ನೀಡಿದ ಸಂಖ್ಯೆಯಲ್ಲ, ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಕಾರ್ಡ್‌ನ ಹಿಂಭಾಗದ ಸಂಖ್ಯೆಯ ಮೂಲಕ ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ.",
        ],
        "PRESSURE": [
            "ನಿಧಾನಿಸಿ — ನಿಜವಾದ ಸಂಸ್ಥೆಗಳು ಚಾಟ್/SMS/ಇಮೇಲ್ ಮೂಲಕ ತಕ್ಷಣ ಖಾತೆ ಸ್ಥಗಿತದ ಬೆದರಿಕೆ ಹಾಕುವುದಿಲ್ಲ.",
            "ಹೇಳಿದ ಗಡುವಿನ ಮೇಲೆ ಕ್ರಮ ತೆಗೆದುಕೊಳ್ಳಬೇಡಿ. ಮೊದಲು ಸ್ವತಂತ್ರವಾಗಿ ಪರಿಶೀಲಿಸಿ.",
        ],
        "REDIRECT": [
            "ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.",
            "ಯಾವುದೇ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ನೀಡಬೇಡಿ.",
            "ಸ್ವತಂತ್ರ, ವಿಶ್ವಾಸಾರ್ಹ ಬ್ಯಾಂಕ್ ಚಾನಲ್ ಮೂಲಕ ಸಂವಹನವನ್ನು ಪರಿಶೀಲಿಸಿ.",
            "ಸೂಕ್ತ ಚಾನಲ್ ಮೂಲಕ ಅನುಮಾನಾಸ್ಪದ ಸಂವಹನವನ್ನು ವರದಿ ಮಾಡಿ.",
        ],
        "EXTRACTION": [
            "ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ.",
            "ಯಾವುದೇ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ನೀಡಬೇಡಿ.",
            "ಸ್ವತಂತ್ರ, ವಿಶ್ವಾಸಾರ್ಹ ಬ್ಯಾಂಕ್ ಚಾನಲ್ ಮೂಲಕ ಸಂವಹನವನ್ನು ಪರಿಶೀಲಿಸಿ.",
            "ಸೂಕ್ತ ಚಾನಲ್ ಮೂಲಕ ಅನುಮಾನಾಸ್ಪದ ಸಂವಹನವನ್ನು ವರದಿ ಮಾಡಿ.",
        ],
    },
}

FINAL_ADVICE_LINE = {
    "en": "If information has already been shared, contact the relevant legitimate service provider immediately.",
    "kn": "ಒಂದು ವೇಳೆ ಈಗಾಗಲೇ ಮಾಹಿತಿ ಹಂಚಿಕೊಂಡಿದ್ದರೆ, ತಕ್ಷಣ ಸಂಬಂಧಿತ ಅಧಿಕೃತ ಸೇವಾ ಪೂರೈಕೆದಾರರನ್ನು ಸಂಪರ್ಕಿಸಿ.",
}

CREDENTIAL_LABEL = {
    "en": {
        "OTP": "OTP", "PIN": "PIN", "CVV": "CVV", "Password": "Password",
        "Card number": "Card number", "Account number": "Account number",
        "UPI PIN": "UPI PIN", "Aadhaar number": "Aadhaar number",
        "Social Security number": "Social Security number",
    },
    "kn": {
        "OTP": "OTP", "PIN": "PIN", "CVV": "CVV", "Password": "ಪಾಸ್‌ವರ್ಡ್",
        "Card number": "ಕಾರ್ಡ್ ಸಂಖ್ಯೆ", "Account number": "ಖಾತೆ ಸಂಖ್ಯೆ",
        "UPI PIN": "UPI ಪಿನ್", "Aadhaar number": "ಆಧಾರ್ ಸಂಖ್ಯೆ",
        "Social Security number": "ಸಾಮಾಜಿಕ ಭದ್ರತಾ ಸಂಖ್ಯೆ",
    },
}

ORG_LABEL = {
    "en": {k: k.title() for k in [
        "bank", "amazon", "paypal", "microsoft", "apple", "government", "income tax", "rbi",
        "courier", "cyber crime", "police", "support team", "electricity board",
        "electricity department", "hr team", "hr department", "recruiter", "trading platform",
        "investment firm", "loan app", "cyber cell", "sub-inspector", "trai", "customer care",
    ]},
    "kn": {
        "bank": "ಬ್ಯಾಂಕ್", "amazon": "Amazon", "paypal": "PayPal", "microsoft": "Microsoft",
        "apple": "Apple", "government": "ಸರ್ಕಾರ", "income tax": "ಆದಾಯ ತೆರಿಗೆ ಇಲಾಖೆ", "rbi": "RBI",
        "courier": "ಕೊರಿಯರ್ ಸಂಸ್ಥೆ", "cyber crime": "ಸೈಬರ್ ಕ್ರೈಂ", "police": "ಪೊಲೀಸ್",
        "support team": "ಬೆಂಬಲ ತಂಡ", "electricity board": "ವಿದ್ಯುತ್ ಮಂಡಳಿ",
        "electricity department": "ವಿದ್ಯುತ್ ಇಲಾಖೆ", "hr team": "HR ತಂಡ", "hr department": "HR ವಿಭಾಗ",
        "recruiter": "ನೇಮಕಾತಿದಾರ", "trading platform": "ಟ್ರೇಡಿಂಗ್ ಪ್ಲಾಟ್‌ಫಾರ್ಮ್",
        "investment firm": "ಹೂಡಿಕೆ ಸಂಸ್ಥೆ", "loan app": "ಸಾಲ ಆ್ಯಪ್", "cyber cell": "ಸೈಬರ್ ಸೆಲ್",
        "sub-inspector": "ಸಬ್-ಇನ್ಸ್‌ಪೆಕ್ಟರ್", "trai": "TRAI", "customer care": "ಗ್ರಾಹಕ ಸೇವೆ",
    },
}

ACTION_TEMPLATE = {
    "en": {
        "click_link": "Click the verification link",
        "follow_instructions": "Follow the provided instructions/link",
        "provide_credential": "Provide {credential}",
        "approve_payment_request": "Approve a payment/collect request",
        "pay_fee": "Pay a fee (registration/processing/deposit)",
        "send_money": "Send money directly",
    },
    "kn": {
        "click_link": "ಪರಿಶೀಲನಾ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡುವುದು",
        "follow_instructions": "ನೀಡಿದ ಸೂಚನೆ/ಲಿಂಕ್ ಅನುಸರಿಸುವುದು",
        "provide_credential": "{credential} ನೀಡುವುದು",
        "approve_payment_request": "ಪಾವತಿ/ಕಲೆಕ್ಟ್ ವಿನಂತಿಯನ್ನು ಅಂಗೀಕರಿಸುವುದು",
        "pay_fee": "ಶುಲ್ಕ ಪಾವತಿಸುವುದು (ನೋಂದಣಿ/ಪ್ರಕ್ರಿಯೆ/ಠೇವಣಿ)",
        "send_money": "ನೇರವಾಗಿ ಹಣ ಕಳುಹಿಸುವುದು",
    },
}

VERDICT_LABEL = {
    "en": {"ATTACK CHAIN DETECTED": "ATTACK CHAIN DETECTED", "LOW-CONFIDENCE / MONITOR": "LOW-CONFIDENCE / MONITOR"},
    "kn": {"ATTACK CHAIN DETECTED": "ದಾಳಿಯ ಸರಪಳಿ ಪತ್ತೆಯಾಗಿದೆ", "LOW-CONFIDENCE / MONITOR": "ಕಡಿಮೆ-ವಿಶ್ವಾಸ / ಗಮನಿಸಿ"},
}


def stage_label(lang: str, stage: str) -> str:
    return STAGE_LABEL[lang].get(stage, stage)


def stage_description(lang: str, stage: str) -> str:
    return STAGE_DESCRIPTION[lang].get(stage, "")


def why_it_matters(lang: str, stage: str) -> str:
    return WHY_IT_MATTERS[lang].get(stage, "")


def attacker_goal(lang: str, stage: str) -> str:
    return ATTACKER_GOAL[lang].get(stage, "")


def risk_level_label(lang: str, level: str) -> str:
    return RISK_LEVEL_LABEL[lang].get(level, level)


def risk_reason(lang: str, stage: str) -> str:
    return RISK_REASON_BY_STAGE[lang].get(stage, "")


def recommendation(lang: str, stage: str) -> List[str]:
    return list(RECOMMENDATION_BY_STAGE[lang].get(stage, []))


def final_advice_line(lang: str) -> str:
    return FINAL_ADVICE_LINE.get(lang, FINAL_ADVICE_LINE["en"])


def credential_label(lang: str, key: str) -> str:
    return CREDENTIAL_LABEL[lang].get(key, key)


def org_label(lang: str, key: str) -> str:
    return ORG_LABEL[lang].get(key, key.title())


def verdict_label(lang: str, verdict: str) -> str:
    return VERDICT_LABEL[lang].get(verdict, verdict)


def render_action(lang: str, action: Dict) -> str:
    template = ACTION_TEMPLATE[lang].get(action["kind"], action["kind"])
    if action["kind"] == "provide_credential":
        return template.format(credential=credential_label(lang, action.get("credential", "")))
    return template