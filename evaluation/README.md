# ScamChain Phase 3.1 — Evaluation Suite

This folder is a **synthetic, local benchmark** for the ScamChain MVP. It does not use external APIs, a live threat feed, or a trained ML model.

## What it measures

- Signal-family recall on labeled suspicious cases
- Attack-chain stage completeness on labeled suspicious cases
- Benign false-positive rate
- Kannada signal coverage
- Simple obfuscation handling
- Per-case failures so the team can see exactly what needs improvement

## Important wording for the hackathon

Do not present these results as real-world accuracy. The cases are synthetic and intentionally small. Use them as a reproducible engineering benchmark and as evidence of testing discipline.

## Run from the ScamChain project root

```bat
python evaluation\run_evaluation.py
```

The script writes:

- `evaluation/results.json`
- `evaluation/results.md`

No third-party test package is required.
