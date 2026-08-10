# Reviewer records

Both adversarial rounds are documented here so that the counts in
`../adversarial_review.md` do not rest on the author's summary alone. A reviewer
record that only lists the findings we survived is not a record.

## What a reader can and cannot check

**Deposited:** the exact instruction given to each reviewer (`round1/*.md`,
`round2/*.md`), the model and configuration each ran under, and the adjudication
rule applied. Every code finding either round produced was independently
re-executed against `guard.py` by the author, and those re-executions are what
the tables report — a reviewer claim we could not reproduce is not counted.

**Not deposited:** full verbatim reviewer output. The records here are the
prompts plus the findings as adjudicated. A reader who wants to check our
adjudication should re-run the prompts — they are reproducible in a way a
transcript is not, since a transcript from a stochastic reviewer is one sample.

**Therefore:** treat the vote counts in `adversarial_review.md` as author-reported
and the *code* findings as independently verified. The regression suite
(`../../tests/test_guard.py`) encodes every one of them, so the findings survive
without trusting anybody's summary — a test that fails is a fact.

## Round 1 — the gate (2026-08-10)

Three reviewers, each given `policy.json`, the tool list, and the six candidate
holes H1–H6. Each was instructed to **refute**, to default to "not a hole" under
uncertainty, and was **not** told the pre-registered prediction. Lenses were
deliberately different rather than three runs of one prompt: reachability,
operational realism, and threat-model coherence. Adjudication: a hole counts on
a 2-of-3 majority, per `../FREEZE.md`.

Model: Claude Opus 4.8 (Anthropic), three independent instances.

Note on completeness: reviewer B rendered no verdict on H6. The `—` in the
verdict table is that gap, not an oversight in transcription, and H6's REFUTED
adjudication therefore rests on two votes rather than three.

## Round 2 — the paper about the gate (2026-08-11)

Two reviewers, both given the draft *and* the artifacts, and both instructed to
attack rather than improve: one as a hostile venue reviewer asked for a
reject/accept verdict and must-fix list, one as a fact-checker asked to find
false or unverifiable statements with a severity rating.

Model: Claude Opus 4.8 (Anthropic), two independent instances.

This round is the one that matters most, because it found that our *fix* from
round 1 had introduced a worse hole than the one it closed. Its findings are in
`../adversarial_review.md` under "Second round", and all five code defects are
now regression-tested.
