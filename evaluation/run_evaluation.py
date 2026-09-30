"""Run the ScamChain synthetic Phase 3.1 benchmark.

Usage from project root:
    python evaluation\run_evaluation.py

The script uses the production deterministic pipeline. It does not call the
FastAPI server and does not require pytest or external services.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.extractor import extract_all
from backend.app.chain_classifier import build_chain
from evaluation.benchmark import CASES

STAGE_ORDER = ["CONTACT", "TRUST_IMPERSONATION", "PRESSURE", "REDIRECT", "EXTRACTION"]


def flatten_signals(extracted: list[Any]) -> set[str]:
    return {key for em in extracted for key in em.signals if key != "generic_greeting"}


def flatten_credentials(extracted: list[Any]) -> set[str]:
    return {cred for em in extracted for cred in em.credentials_requested}


def expected_signal_types(expected_chain: list[str]) -> set[str]:
    mapping = {
        "TRUST_IMPERSONATION": "impersonation",
        "PRESSURE": "urgency",
        "REDIRECT": "redirect",
        "EXTRACTION": "extraction",
    }
    return {mapping[s] for s in expected_chain if s in mapping}


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    extracted = extract_all(case["messages"])
    result = build_chain(extracted)
    detected_signals = sorted(flatten_signals(extracted))
    detected_credentials = sorted(flatten_credentials(extracted))
    actual_chain = result["chain"]
    actual_max_stage = result["max_stage"]

    required_signals = set(case.get("required_signals", []))
    required_credentials = set(case.get("required_credentials", []))

    expected_chain = case.get("expected_chain")
    expected_from_chain = expected_signal_types(expected_chain or [])
    required_signals |= expected_from_chain

    detected_required = required_signals & set(detected_signals)
    signal_ok = detected_required == required_signals
    credential_ok = required_credentials.issubset(set(detected_credentials))

    if expected_chain:
        chain_hits = len([stage for stage in expected_chain if stage in actual_chain])
        chain_completeness = round(chain_hits / len(expected_chain), 4) if expected_chain else 1.0
        chain_ok = actual_chain == expected_chain
        expected_max_stage = expected_chain[-1]
        max_stage_ok = actual_max_stage == expected_max_stage
    else:
        chain_completeness = None
        chain_ok = None
        expected_max_stage = case.get("max_stage")
        max_stage_ok = actual_max_stage == expected_max_stage if expected_max_stage else True

    passed = signal_ok and credential_ok and max_stage_ok and (chain_ok if chain_ok is not None else True)

    return {
        "id": case["id"],
        "group": case["group"],
        "passed": passed,
        "detected_signals": detected_signals,
        "required_signals": sorted(required_signals),
        "missing_signals": sorted(required_signals - set(detected_signals)),
        "detected_credentials": detected_credentials,
        "required_credentials": sorted(required_credentials),
        "missing_credentials": sorted(required_credentials - set(detected_credentials)),
        "actual_chain": actual_chain,
        "expected_chain": expected_chain,
        "chain_completeness": chain_completeness,
        "actual_max_stage": actual_max_stage,
        "expected_max_stage": expected_max_stage,
        "max_stage_ok": max_stage_ok,
        "signal_ok": signal_ok,
        "credential_ok": credential_ok,
    }


def pct(n: int, d: int) -> float:
    return round((n / d) * 100, 2) if d else 0.0


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    suspicious = [r for r in rows if r["group"] != "benign"]
    benign = [r for r in rows if r["group"] == "benign"]
    all_required = sum(len(r["required_signals"]) for r in suspicious)
    all_detected = sum(len(r["required_signals"]) - len(r["missing_signals"]) for r in suspicious)
    chain_rows = [r for r in suspicious if r["chain_completeness"] is not None]
    avg_chain = round(sum(r["chain_completeness"] for r in chain_rows) / len(chain_rows), 4) if chain_rows else 0
    false_positive = sum(bool(r["detected_signals"]) for r in benign)
    full_pass = sum(r["passed"] for r in suspicious)
    kannada = [r for r in rows if r["group"] == "kannada"]
    obfuscation = [r for r in rows if r["group"] == "obfuscation"]
    return {
        "total_cases": len(rows),
        "suspicious_cases": len(suspicious),
        "benign_cases": len(benign),
        "benchmark_case_pass_rate_percent": pct(full_pass, len(suspicious)),
        "required_signal_recall_percent": pct(all_detected, all_required),
        "average_chain_completeness_percent": round(avg_chain * 100, 2),
        "benign_false_positive_rate_percent": pct(false_positive, len(benign)),
        "kannada_case_pass_rate_percent": pct(sum(r["passed"] for r in kannada), len(kannada)),
        "obfuscation_case_pass_rate_percent": pct(sum(r["passed"] for r in obfuscation), len(obfuscation)),
    }


def write_markdown(rows: list[dict[str, Any]], summary: dict[str, Any], path: Path) -> None:
    lines = [
        "# ScamChain Phase 3.1 — Evaluation Results",
        "",
        "> Synthetic benchmark only. These results are not real-world accuracy estimates.",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        label = key.replace("_", " ").title()
        suffix = "%" if "percent" in key else ""
        lines.append(f"- **{label}:** {value}{suffix}")
    lines += ["", "## Per-case results", "", "| Case | Group | Pass | Max stage | Expected max | Missing signals |", "|---|---|---:|---|---|---|"]
    for r in rows:
        missing = ", ".join(r["missing_signals"]) or "—"
        lines.append(f"| {r['id']} | {r['group']} | {'✅' if r['passed'] else '❌'} | {r['actual_max_stage']} | {r['expected_max_stage'] or '—'} | {missing} |")
    lines += ["", "## How to interpret failures", "", "A failed synthetic case is a debugging signal. It does not mean the project is unusable; it tells the team which evidence rule, stage relationship, or benign control needs attention before the next iteration."]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    rows = [evaluate_case(case) for case in CASES]
    summary = build_summary(rows)
    results = {"benchmark": "synthetic", "summary": summary, "cases": rows}

    out_json = ROOT / "evaluation" / "results.json"
    out_md = ROOT / "evaluation" / "results.md"
    out_json.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(rows, summary, out_md)

    print("ScamChain Phase 3.1 synthetic evaluation")
    print("=" * 44)
    for key, value in summary.items():
        label = key.replace("_", " ")
        suffix = "%" if "percent" in key else ""
        print(f"{label}: {value}{suffix}")
    print("\nFailures:")
    failures = [r for r in rows if not r["passed"]]
    if not failures:
        print("None")
    else:
        for r in failures:
            print(f"- {r['id']}: missing={r['missing_signals']}, actual_chain={r['actual_chain']}, expected={r['expected_chain']}")
    print(f"\nWrote: {out_json}")
    print(f"Wrote: {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
