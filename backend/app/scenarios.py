"""
scenarios.py
A single, central registry of synthetic demo scenarios.

IMPORTANT: none of these scenarios has its own analysis code. Every one of
them is just a list of English messages that the SAME extractor/classifier/
graph_builder/explainer pipeline processes like any other input. That is
the point: it demonstrates ScamChain is a general attack-chain
reconstructor, not nine hardcoded detectors (see PIPELINE_FIXES.md and the
"do not create separate analysis pipelines" product requirement).

All content below is entirely fictional (fake names, fake org labels, fake
non-resolving .xyz/.tk URLs, no real phone numbers or payment destinations)
and written purely for security-awareness demonstration purposes - see
"Safety notes" in README.md.

Message content is in English on purpose: the rule-based lexicons in
extractor.py match English keywords, so English input is what the detector
actually understands today. Scenario LABELS (name/description) are
provided in both English and Kannada for the picker UI; message CONTENT is
not translated - see README "Limitations".
"""

from typing import List, TypedDict


class Scenario(TypedDict):
    id: str
    label_en: str
    label_kn: str
    description_en: str
    description_kn: str
    messages: List[str]


SCENARIOS: List[Scenario] = [
    {
        "id": "bank_otp",
        "label_en": "Bank OTP / KYC",
        "label_kn": "ಬ್ಯಾಂಕ್ OTP / KYC",
        "description_en": "The original primary demo - impersonation, urgency, a phishing link, then an OTP request.",
        "description_kn": "ಮೂಲ ಪ್ರಮುಖ ಡೆಮೊ — ಸೋಗು, ತುರ್ತು, ಫಿಶಿಂಗ್ ಲಿಂಕ್, ನಂತರ OTP ಬೇಡಿಕೆ.",
        "messages": [
            "Hi, I am from your bank.",
            "There is an urgent problem with your account. It will be suspended within 24 hours.",
            "Click this link to verify your account: http://secure-bankverify.xyz/login",
            "Please enter your OTP to complete verification.",
        ],
    },
    {
        "id": "upi_payment",
        "label_en": "UPI Payment Request",
        "label_kn": "UPI ಪಾವತಿ ವಿನಂತಿ",
        "description_en": "A fake refund that actually requires approving a payment (collect) request, not receiving money.",
        "description_kn": "ಹಣ ಸ್ವೀಕರಿಸುವ ಬದಲು ಪಾವತಿ (ಕಲೆಕ್ಟ್) ವಿನಂತಿಯನ್ನು ಅಂಗೀಕರಿಸುವಂತೆ ಕೇಳುವ ನಕಲಿ ಮರುಪಾವತಿ.",
        "messages": [
            "Hello, greetings! This is customer care from your UPI app.",
            "We are processing a refund of Rs. 2000 to your account, but we noticed unusual activity - please confirm to proceed.",
            "This refund will expire immediately if not approved today.",
            "Please approve the collect request sent to your UPI app to receive the refund.",
        ],
    },
    {
        "id": "fake_customer_care",
        "label_en": "Fake Customer Care",
        "label_kn": "ನಕಲಿ ಗ್ರಾಹಕ ಸೇವೆ",
        "description_en": "Unsolicited 'support' contact that pushes the victim to install an app and hand over a password/OTP.",
        "description_kn": "ಬಳಕೆದಾರರನ್ನು ಆ್ಯಪ್ ಸ್ಥಾಪಿಸಿ ಪಾಸ್‌ವರ್ಡ್/OTP ನೀಡುವಂತೆ ಒತ್ತಾಯಿಸುವ ಅನಪೇಕ್ಷಿತ 'ಬೆಂಬಲ' ಸಂಪರ್ಕ.",
        "messages": [
            "This is Amazon customer support team regarding your recent order.",
            "There is unusual activity on your account and it will be blocked immediately if not resolved.",
            "Please download this app to continue the verification process.",
            "Enter your password and OTP to verify your identity.",
        ],
    },
    {
        "id": "digital_arrest",
        "label_en": "Digital Arrest",
        "label_kn": "ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್",
        "description_en": "Fake law-enforcement authority uses fear and isolation to demand an immediate 'verification' transfer.",
        "description_kn": "ನಕಲಿ ಕಾನೂನು ಜಾರಿ ಅಧಿಕಾರಿ, ಭಯ ಮತ್ತು ಪ್ರತ್ಯೇಕತೆ ಬಳಸಿ ತಕ್ಷಣದ 'ಪರಿಶೀಲನಾ' ವರ್ಗಾವಣೆ ಬೇಡುತ್ತಾರೆ.",
        "messages": [
            "This is the cyber crime cell regarding a case registered under your name.",
            "An FIR will be filed against you unless you cooperate immediately.",
            "Do not disconnect the call and do not tell anyone about this investigation - stay on the line.",
            "To avoid arrest, transfer the verification amount immediately to the given account and share your Aadhaar number.",
        ],
    },
    {
        "id": "fake_job",
        "label_en": "Fake Job Offer",
        "label_kn": "ನಕಲಿ ಉದ್ಯೋಗ ಕೊಡುಗೆ",
        "description_en": "An attractive work-from-home offer that turns into a registration-fee and bank-details demand.",
        "description_kn": "ಆಕರ್ಷಕ ಮನೆಯಿಂದ ಕೆಲಸದ ಕೊಡುಗೆ, ನಂತರ ನೋಂದಣಿ ಶುಲ್ಕ ಮತ್ತು ಬ್ಯಾಂಕ್ ವಿವರ ಬೇಡಿಕೆಯಾಗಿ ಬದಲಾಗುತ್ತದೆ.",
        "messages": [
            "Congratulations! You have been selected for a work-from-home job with attractive salary.",
            "This is the HR team of a leading company confirming your selection.",
            "Only limited slots are available - complete your registration today to confirm your seat.",
            "Please pay the registration fee and share your bank account number to process your first payment.",
        ],
    },
    {
        "id": "electricity",
        "label_en": "Electricity Disconnection",
        "label_kn": "ವಿದ್ಯುತ್ ಸಂಪರ್ಕ ಕಡಿತ",
        "description_en": "A fake utility-board threat to disconnect power tonight unless an urgent online payment is made.",
        "description_kn": "ತಕ್ಷಣ ಆನ್‌ಲೈನ್ ಪಾವತಿ ಮಾಡದಿದ್ದರೆ ಇಂದು ರಾತ್ರಿ ವಿದ್ಯುತ್ ಕಡಿತಗೊಳಿಸುವ ನಕಲಿ ಬೆದರಿಕೆ.",
        "messages": [
            "This is a message from your electricity board regarding your account.",
            "Your power will be disconnected tonight due to an unpaid bill.",
            "Click this link immediately to make the payment and avoid disconnection: http://eb-billpay.xyz/pay",
            "Enter your card number to complete the payment and prevent disconnection.",
        ],
    },
    {
        "id": "courier",
        "label_en": "Courier Scam",
        "label_kn": "ಕೊರಿಯರ್ ವಂಚನೆ",
        "description_en": "A parcel supposedly held at customs, requiring a small 'fee' and then card details to release it.",
        "description_kn": "ಕಸ್ಟಮ್ಸ್‌ನಲ್ಲಿ ತಡೆಹಿಡಿಯಲಾಗಿದೆ ಎಂದು ಹೇಳುವ ಪಾರ್ಸೆಲ್, ಸಣ್ಣ 'ಶುಲ್ಕ' ಮತ್ತು ಕಾರ್ಡ್ ವಿವರ ಕೇಳುತ್ತದೆ.",
        "messages": [
            "Dear customer, this is regarding your recent order.",
            "We are from the courier company. Your parcel is held at customs due to unusual activity on your address.",
            "Failure to respond within 2 hours will result in your parcel being returned. Pay a small customs fee immediately to release it.",
            "Tap this link to pay the pending customs fee: http://parcel-customs-fee.tk/pay",
            "Enter your card number and CVV to complete the payment.",
        ],
    },
    {
        "id": "fake_loan",
        "label_en": "Fake Loan App",
        "label_kn": "ನಕಲಿ ಸಾಲ ಆ್ಯಪ್",
        "description_en": "A pre-approved instant loan offer that requires a processing fee and identity documents up front.",
        "description_kn": "ಮುಂಗಡವಾಗಿ ಪ್ರಕ್ರಿಯೆ ಶುಲ್ಕ ಮತ್ತು ಗುರುತಿನ ದಾಖಲೆ ಕೇಳುವ ಪೂರ್ವ-ಅನುಮೋದಿತ ತಕ್ಷಣ ಸಾಲ ಕೊಡುಗೆ.",
        "messages": [
            "Congratulations! You are pre-approved for an instant personal loan up to Rs. 5,00,000.",
            "This offer expires today - act now to claim your loan.",
            "Download the loan app and pay a small processing fee to release the loan amount.",
            "Also share your Aadhaar number and account number for verification before disbursal.",
        ],
    },
    {
        "id": "investment",
        "label_en": "Investment Scam",
        "label_kn": "ಹೂಡಿಕೆ ವಂಚನೆ",
        "description_en": "A trading platform promising guaranteed returns, then pressuring a transfer to 'activate' the account.",
        "description_kn": "ಖಚಿತ ಲಾಭದ ಭರವಸೆ ನೀಡುವ ಟ್ರೇಡಿಂಗ್ ಪ್ಲಾಟ್‌ಫಾರ್ಮ್, ನಂತರ ಖಾತೆ 'ಸಕ್ರಿಯಗೊಳಿಸಲು' ವರ್ಗಾವಣೆಗೆ ಒತ್ತಾಯಿಸುತ್ತದೆ.",
        "messages": [
            "Hi! Congratulations, you've been selected to join our exclusive trading platform with guaranteed daily returns.",
            "Our investment firm's senior analysts guarantee you can double your investment within a week.",
            "Limited slots are open today only - invest now before the offer expires.",
            "Transfer the investment amount to this account and share your account number to activate your trading account.",
        ],
    },
]

SCENARIOS_BY_ID = {s["id"]: s for s in SCENARIOS}
