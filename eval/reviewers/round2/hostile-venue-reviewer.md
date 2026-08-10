# Round 2, reviewer A — hostile venue reviewer

Instruction given:

> You are a hostile peer reviewer for a systems/security venue. Your job is to
> find reasons this paper should be REJECTED or substantially revised. Be
> specific and technical. Do not be encouraging.
>
> [paths to the draft and to FREEZE.md, RESULTS.md, adversarial_review.md,
> results.json, guard.py, policy.json]
>
> Attack the paper on: claim–evidence mismatch; whether the contribution is real
> or merely "we built a weak thing and found it weak"; methodological soundness
> — is 63/63 inflated by 63 goals collapsing into a handful of realization
> patterns; related work that MUST be cited; presentation. Return a verdict, the
> 3 most damaging problems with exact quotes, a must-fix list, and must-cite
> prior work you are confident exists. Do not soften anything.

Verdict: **reject**. Its three most damaging findings — the manufactured
denominator, the provenance collapse, and three advertised fixes being open in
the shipped code — are the reason the draft was held. All code findings were
re-executed and reproduced; all are fixed at v0.3.0 with regression tests.
