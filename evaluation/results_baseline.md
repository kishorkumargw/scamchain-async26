# ScamChain Phase 3.1 — Evaluation Results

> Synthetic benchmark only. These results are not real-world accuracy estimates.

## Summary

- **Total Cases:** 28
- **Suspicious Cases:** 20
- **Benign Cases:** 8
- **Benchmark Case Pass Rate Percent:** 90.0%
- **Required Signal Recall Percent:** 98.0%
- **Average Chain Completeness Percent:** 100.0%
- **Benign False Positive Rate Percent:** 37.5%
- **Kannada Case Pass Rate Percent:** 75.0%
- **Obfuscation Case Pass Rate Percent:** 100.0%

## Per-case results

| Case | Group | Pass | Max stage | Expected max | Missing signals |
|---|---|---:|---|---|---|
| scenario_bank_otp | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_upi_payment | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_fake_customer_care | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_digital_arrest | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_fake_job | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_electricity | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_courier | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_fake_loan | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| scenario_investment | scenario | ✅ | EXTRACTION | EXTRACTION | — |
| stage_contact_only | partial | ✅ | CONTACT | CONTACT | — |
| stage_impersonation | partial | ✅ | TRUST_IMPERSONATION | TRUST_IMPERSONATION | — |
| stage_pressure | partial | ✅ | PRESSURE | PRESSURE | — |
| stage_redirect | partial | ❌ | REDIRECT | REDIRECT | — |
| stage_extraction | partial | ✅ | EXTRACTION | EXTRACTION | — |
| benign_meeting | benign | ✅ | CONTACT | CONTACT | — |
| benign_parcel_delivered | benign | ✅ | CONTACT | CONTACT | — |
| benign_official_app | benign | ❌ | TRUST_IMPERSONATION | CONTACT | — |
| benign_power_bill | benign | ❌ | TRUST_IMPERSONATION | CONTACT | — |
| benign_job_interview | benign | ✅ | CONTACT | CONTACT | — |
| benign_company_portal | benign | ❌ | REDIRECT | CONTACT | — |
| benign_bank_statement | benign | ❌ | TRUST_IMPERSONATION | CONTACT | — |
| benign_greeting | benign | ✅ | CONTACT | CONTACT | — |
| kannada_bank_chain | kannada | ✅ | EXTRACTION | EXTRACTION | — |
| kannada_credential | kannada | ✅ | EXTRACTION | EXTRACTION | — |
| kannada_mixed_language | kannada | ❌ | EXTRACTION | EXTRACTION | redirect |
| kannada_payment | kannada | ✅ | EXTRACTION | EXTRACTION | — |
| obfuscated_otp | obfuscation | ✅ | EXTRACTION | EXTRACTION | — |
| obfuscated_password_click | obfuscation | ✅ | EXTRACTION | EXTRACTION | — |

## How to interpret failures

A failed synthetic case is a debugging signal. It does not mean the project is unusable; it tells the team which evidence rule, stage relationship, or benign control needs attention before the next iteration.
