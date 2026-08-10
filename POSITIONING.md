# What this is, and what it is not

This document exists so that no one — including a future maintainer — mistakes
this project for a safety guarantee. The evaluation in `eval/` is the evidence
behind every sentence here.

## The claim we make

**An auditable, bounded mediation layer for browser-agent actions.**

Bounded: it forces a human decision on any goal whose every realization requires
an ask-class action, regardless of how the attack is phrased — and it states
exactly which goals fall outside that set. Auditable: every verdict is logged
with its reason, so a reviewer can see what was allowed and why. Mediation, not
prevention: it routes a security decision to a human; it does not make the
decision safe.

## The claim we do NOT make

We do not claim the agent is safe with this installed. The guarantee is exactly
as strong as the proposition *"the allow tier is effect-free"*, and adversarial
review showed that proposition is false: 63 of 63 corpus attacker goals have a
realization that stays inside the allow tier. Four of the sharpest such channels
were closed in v0.2.0; the reachability count did not change; more channels
almost certainly exist. `eval/adversarial_review.md` lists the ones we know
about and have not fixed.

## Why we publish the failures

A security product that overstates its guarantee loses all credibility the first
time one hole is found. A product that publishes its own holes keeps credibility
even as holes are found, because the reader can calibrate. This is a deliberate
trade: we give up the marketing claim "safe" in exchange for the durable claim
"honest about its boundary." For a governance layer that expects to be attacked,
the second is worth more.

## How this sits in the MOBIUS line

The same shape recurs across MOBIUS governance work — the secretary's RCGov
write-gate, the capacity gate, the two-stage abstain: a content-blind, total,
explainable check that bounds *what can happen* rather than guessing *what is
malicious*. The recommendation carried out here applies to all of them: sell the
bounded, auditable property and publish the boundary; never sell "safe."

## The process lesson

The most valuable step in this project was not building the gate. It was handing
the gate to independent adversarial reviewers instructed to refute our findings.
They refuted three claims we thought were holes (they were declared scope), and
found four holes we had missed that were worse than anything we predicted. Self-
assessment did not surface them; adversarial assessment did, in minutes. Any
MOBIUS artifact that carries a safety or correctness claim should pass through
that step before it is trusted — the same move that put a MAJOR finding into all
six theory papers on their adversarial pass. The gate is the deliverable; the
adversarial process is the reason to believe it.
