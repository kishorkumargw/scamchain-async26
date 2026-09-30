# ScamChain — Final Submission Checklist

## Before pushing

- [ ] Run `python evaluation\run_evaluation.py` and verify the benchmark completes.
- [ ] Start backend with `python -m uvicorn app.main:app --reload --port 8000`.
- [ ] Start frontend with `python -m http.server 5500`.
- [ ] Run the Bank OTP demo from the scenario picker.
- [ ] Test English and Kannada display.
- [ ] Verify the evidence graph renders from the local vendored library.
- [ ] Verify no API key is present anywhere in the repository.
- [ ] Review `git status` before commit.

## Recommended commit

```bat
git add .
git commit -m "Final offline submission: harden ScamChain MVP"
git push origin main
```

## What to tell judges

ScamChain is an explainable attack-chain reconstructor. It connects multiple scam signals into an evidence graph, reconstructs the attack stage-by-stage, explains the evidence, and gives a defensive response. The final submission intentionally uses a deterministic local engine so the core demo is reproducible without API keys or external model availability.

## Hackathon compliance reminder

The official participant instructions require submitted projects to be open source on GitHub, disclose prior/existing work, distinguish what existed before the hackathon from what was built during it, use appropriately licensed assets, and include enough documentation for judges to reproduce the core functionality.
