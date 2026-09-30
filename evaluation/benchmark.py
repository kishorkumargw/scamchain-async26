"""Synthetic evaluation cases for ScamChain Phase 3.1.

All messages are synthetic security-awareness examples. Expected labels are
explicitly defined here so the benchmark is reproducible and auditable.
"""

CASES = [
    # Full existing demo scenarios: expected chain is derived from the
    # intended progression visible in the product, not from current output.
    {
        "id": "scenario_bank_otp",
        "group": "scenario",
        "messages": [
            "Hi, I am from your bank.",
            "There is an urgent problem with your account. It will be suspended within 24 hours.",
            "Click this link to verify your account: http://secure-bankverify.xyz/login",
            "Please enter your OTP to complete verification.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_upi_payment",
        "group": "scenario",
        "messages": [
            "Hello, greetings! This is customer care from your UPI app.",
            "We are processing a refund of Rs. 2000 to your account, but we noticed unusual activity - please confirm to proceed.",
            "This refund will expire immediately if not approved today.",
            "Please approve the collect request sent to your UPI app to receive the refund.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_fake_customer_care",
        "group": "scenario",
        "messages": [
            "This is Amazon customer support team regarding your recent order.",
            "There is unusual activity on your account and it will be blocked immediately if not resolved.",
            "Please download this app to continue the verification process.",
            "Enter your password and OTP to verify your identity.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_digital_arrest",
        "group": "scenario",
        "messages": [
            "This is the cyber crime cell regarding a case registered under your name.",
            "An FIR will be filed against you unless you cooperate immediately.",
            "Do not disconnect the call and do not tell anyone about this investigation - stay on the line.",
            "To avoid arrest, transfer the verification amount immediately to the given account and share your Aadhaar number.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "EXTRACTION"],
    },
    {
        "id": "scenario_fake_job",
        "group": "scenario",
        "messages": [
            "Congratulations! You have been selected for a work-from-home job with attractive salary.",
            "This is the HR team of a leading company confirming your selection.",
            "Only limited slots are available - complete your registration today to confirm your seat.",
            "Please pay the registration fee and share your bank account number to process your first payment.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "EXTRACTION"],
    },
    {
        "id": "scenario_electricity",
        "group": "scenario",
        "messages": [
            "This is a message from your electricity board regarding your account.",
            "Your power will be disconnected tonight due to an unpaid bill.",
            "Click this link immediately to make the payment and avoid disconnection: http://eb-billpay.xyz/pay",
            "Enter your card number to complete the payment and prevent disconnection.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_courier",
        "group": "scenario",
        "messages": [
            "Dear customer, this is regarding your recent order.",
            "We are from the courier company. Your parcel is held at customs due to unusual activity on your address.",
            "Failure to respond within 2 hours will result in your parcel being returned. Pay a small customs fee immediately to release it.",
            "Tap this link to pay the pending customs fee: http://parcel-customs-fee.tk/pay",
            "Enter your card number and CVV to complete the payment.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_fake_loan",
        "group": "scenario",
        "messages": [
            "Congratulations! You are pre-approved for an instant personal loan up to Rs. 5,00,000.",
            "This offer expires today - act now to claim your loan.",
            "Download the loan app and pay a small processing fee to release the loan amount.",
            "Also share your Aadhaar number and account number for verification before disbursal.",
        ],
        "expected_chain": ["CONTACT", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "scenario_investment",
        "group": "scenario",
        "messages": [
            "Hi! Congratulations, you've been selected to join our exclusive trading platform with guaranteed daily returns.",
            "Our investment firm's senior analysts guarantee you can double your investment within a week.",
            "Limited slots are open today only - invest now before the offer expires.",
            "Transfer the investment amount to this account and share your account number to activate your trading account.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "EXTRACTION"],
    },

    # Focused stage/counterfactual cases.
    {
        "id": "stage_contact_only",
        "group": "partial",
        "messages": ["Hi, I am checking in about the project."],
        "expected_chain": ["CONTACT"],
    },
    {
        "id": "stage_impersonation",
        "group": "partial",
        "messages": ["Hi, I am from your bank."],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION"],
    },
    {
        "id": "stage_pressure",
        "group": "partial",
        "messages": ["Your account will be suspended within 24 hours."],
        "expected_chain": ["CONTACT", "PRESSURE"],
    },
    {
        "id": "stage_redirect",
        "group": "partial",
        "messages": ["Click this link to verify your account: http://secure-bankverify.xyz/login"],
        "expected_chain": ["CONTACT", "REDIRECT"],
    },
    {
        "id": "stage_extraction",
        "group": "partial",
        "messages": ["Please enter your OTP to complete verification."],
        "expected_chain": ["CONTACT", "EXTRACTION"],
    },

    # Benign controls. Some intentionally resemble ordinary operational
    # language to expose over-broad rules.
    {
        "id": "benign_meeting",
        "group": "benign",
        "messages": ["Hello everyone, the project meeting is at 5 PM in Lab 204."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_parcel_delivered",
        "group": "benign",
        "messages": ["Your parcel was delivered this afternoon. No action is required."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_official_app",
        "group": "benign",
        "messages": ["Your monthly account statement is available in the official bank app."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_power_bill",
        "group": "benign",
        "messages": ["Your electricity bill is due next week. Please use the official app when you are ready to pay."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_job_interview",
        "group": "benign",
        "messages": ["Thank you for applying. Your interview is scheduled for Friday at 11 AM."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_company_portal",
        "group": "benign",
        "messages": ["Please click the company portal to view the agenda for tomorrow's meeting."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_bank_statement",
        "group": "benign",
        "messages": ["The bank statement for August is ready for download. Please review it when convenient."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },
    {
        "id": "benign_greeting",
        "group": "benign",
        "messages": ["Hello, hope you are doing well today."],
        "expected_signals": [],
        "max_stage": "CONTACT",
    },

    # Kannada: focused, phrase-based coverage cases.
    {
        "id": "kannada_bank_chain",
        "group": "kannada",
        "messages": [
            "ನಮಸ್ಕಾರ, ನಾನು ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ನಿಂದ ಮಾತನಾಡುತ್ತಿದ್ದೇನೆ.",
            "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ತಕ್ಷಣ ಪರಿಶೀಲಿಸಬೇಕು.",
            "ಈ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಿ ಮತ್ತು ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ.",
            "OTP ನಮೂದಿಸಿ ಮತ್ತು ಪರಿಶೀಲನೆ ಪೂರ್ಣಗೊಳಿಸಿ.",
        ],
        "expected_chain": ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"],
    },
    {
        "id": "kannada_credential",
        "group": "kannada",
        "messages": ["ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಲು OTP ನಮೂದಿಸಿ."],
        "required_signals": ["extraction"],
        "required_credentials": ["OTP"],
        "max_stage": "EXTRACTION",
    },
    {
        "id": "kannada_mixed_language",
        "group": "kannada",
        "messages": ["ನಿಮ್ಮ bank account ಅನ್ನು ತಕ್ಷಣ verify ಮಾಡಿ. ಈ link click ಮಾಡಿ ಮತ್ತು OTP enter ಮಾಡಿ."],
        "required_signals": ["urgency", "redirect", "extraction"],
        "required_credentials": ["OTP"],
        "max_stage": "EXTRACTION",
    },
    {
        "id": "kannada_payment",
        "group": "kannada",
        "messages": ["ಬ್ಯಾಂಕ್ ಅಧಿಕಾರಿಯಿಂದ ಸಂದೇಶ. ತಕ್ಷಣ ಪಾವತಿ ಮಾಡಿ ಮತ್ತು ಹಣ ಕಳುಹಿಸಿ."],
        "required_signals": ["impersonation", "urgency", "extraction"],
        "max_stage": "EXTRACTION",
    },

    # Obfuscation robustness.
    {
        "id": "obfuscated_otp",
        "group": "obfuscation",
        "messages": ["Please enter your O.T.P to complete verification."],
        "required_signals": ["extraction"],
        "required_credentials": ["OTP"],
        "max_stage": "EXTRACTION",
    },
    {
        "id": "obfuscated_password_click",
        "group": "obfuscation",
        "messages": ["C L I C K the link and enter your P.A.S.S.W.O.R.D."],
        "required_signals": ["redirect", "extraction"],
        "required_credentials": ["Password"],
        "max_stage": "EXTRACTION",
    },
]
