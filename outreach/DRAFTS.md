# Outreach drafts

**Final, ready-to-paste posts live in `POST_linkedin_A.md` and `POST_medium.md`.**
This file keeps the alternates and the working notes. Nothing here has been
posted; posting is manual (no API access to either platform from this toolchain).

## How to post

1. **LinkedIn** — paste the body of `POST_linkedin_A.md` (2,534 characters, under
   the 3,000 limit) and attach `figure_hero.png`. The hook fits above the
   "see more" fold.
2. **Medium** — paste `POST_medium.md` from the title down. Attach
   `figure_full_light.png` as the hero, or split it: the ladder near §1, the
   cost bars near §8. Tags are listed at the top of that file.
3. Post LinkedIn first, then Medium a day later linking back — or both at once;
   the DOI and repo links are live either way (verified 2026-08-11).

## Alternates and notes

Drafts only. Posting is the owner's decision; nothing here has been published to
any external platform. Every number is from
`eval/results_policy_v0.3.1.json` or from a verdict re-run against `guard.py`.

Images, already exported (neither platform renders HTML):
- `outreach/figure_hero.png` (2360×2000) — LinkedIn. Headline, the action ladder, the four headline numbers.
- `outreach/figure_full_light.png` (2360×4240) — Medium. Everything, including the review rounds and the cost bars.
Sources: `figure.html` (theme-aware, also published as an artifact), `figure_export.html` / `figure_hero.html` (light-locked, used for the PNGs).

---

## LinkedIn

**Draft A — the finding (recommended)**

We built a security layer for browser agents, then published the proof that it
doesn't fully work. Here's why that was the right call.

AI agents that drive your browser inherit everything your browser has: your
logged-in sessions, your cookies, your authority. A malicious page can hide
instructions in its own text, and if the agent follows them, it acts as you. The
usual defence is to detect the malicious text — useful, and never complete,
because an attacker can always rephrase.

So we built the other half: a gate that never reads the attack at all. It
classifies each browser action by what it can do — read a page, click a button,
run code — and requires human approval before anything irreversible. An injection
that slips past every detector still can't reach the send button alone.

Then we measured it against 63 attacker goals from a published corpus, and asked
the question we least wanted answered: can any goal be reached without ever
triggering a prompt?

Yes. Three patterns get through, and between them they cover all 63.

Two of those three turned out not to be flaws — independent reviewers, told to
refute us, unanimously ruled that reading an authenticated page is what a
browser agent is *for*. The third is a genuine gap: forms that commit on input,
with no click to gate.

The reviewers then found five channels we'd missed. The sharpest: a screenshot
of your authenticated banking page can be dragged onto an upload box on the
attacker's own page, with no gated action anywhere.

We fixed four of them. Then a second review round examined the paper — and found
our fix had opened a worse hole than the one it closed. The component we'd added
learned which site each tab was on by scanning tool output, so a malicious page
could forge its own identity by printing one line in its body. A third round
found our fix for *that* was incomplete too.

Twice in a row, a fix written in response to a finding carried a hole of the
same class as the one it closed. That is the lesson worth passing on: **a fix
needs the same adversarial review as the thing it fixes.**

The gate is MIT-licensed and installable in about ten minutes. Its residual
attack surface is published alongside it, because a security tool that only
reports what it survived isn't evidence.

github.com/mobius-style/mobius-browser-guard

#AISecurity #PromptInjection #AIAgents #AppSec

---

**Draft B — the shorter, method-first version**

Three independent reviewers, told to refute my findings, rejected three of them
as non-issues — then found five holes I'd missed that were worse than anything
I'd predicted.

That's the whole story of shipping a security layer for browser agents this
week, and the reason I now treat adversarial review as a required stage rather
than a nice-to-have.

The artifact: a permission gate for AI agents that drive Chrome. It never reads
the attack — it classifies each action by what it can do and asks a human before
anything irreversible. Cheap to run: on sites you've allowlisted it asks for
nothing until you commit a change.

The finding: three patterns defeat it, covering all 63 attacker goals in the
corpus I tested against. Two are declared scope. One is real.

The uncomfortable part: my fix for the reviewers' findings introduced a worse
hole than it closed — and my fix for *that* was incomplete. Both caught only
because I kept running adversarial rounds, the later ones on the paper rather
than the code.

Published with its residual attack surface, its deviations, and its reviewer
records: github.com/mobius-style/mobius-browser-guard

---

## Medium

**Working title:** I Built a Defence for Browser Agents, Then Published Proof It
Doesn't Fully Work

**Subtitle:** Three patterns defeat a detection-independent action gate. Two of
them aren't bugs. The third — and what adversarial review did to my fix — is the
part worth reading.

**Structure**

1. *The setup.* Browser agents inherit your authenticated session. Indirect
   prompt injection turns that into an attack surface. Detection is fallible by
   construction; a defence that never reads the attack has no false-negative
   surface with respect to attacker cleverness. Frame the two layers.
2. *The gate.* The action ladder: reads free, actuation gated, unknown fails
   closed. The `browser_batch` hole — a wrapper tool that composes actions voids
   a naive gate, and wrapper tools are everywhere because they're a latency
   optimisation. Screenshot of the ladder table from the figure.
3. *The registered question.* Why "did it block the attacks?" is a worthless
   question when you wrote both the mapping and the gate, and what to ask
   instead. The commitment device, and why it isn't a real pre-registration.
4. *The negative result.* Three patterns, 63 goals. Reviewers refuting two of
   three as declared scope. The distinction that matters: "the gate fails at
   something it claims" vs "the gate doesn't attempt this, and says so".
5. *What the reviewers found.* Screenshot → upload widget. The recording
   exporter. Writing into the attacker's own DOM. Subdomain over-matching. Form
   poisoning, which is still unfixed because the prompt shows the click, not the
   contents.
6. *The fix that broke it.* Origin predicates, and the tab-origin learner that
   read attacker-controlled text. Why this is the most useful paragraph in the
   piece.
7. *What can honestly be claimed.* Mediated Effect Confinement, stated plainly,
   and the sentence that bounds it: the guarantee is exactly as strong as the
   claim that the allow tier is effect-free, and it isn't.
8. *The cost.* 0 prompts for reading, 1 per commit, 1.33 per off-allowlist
   research task, 85.7% of benign calls silent. And the number that isn't
   measured: how a tired human answers the fifth prompt of the afternoon.
9. *Two takeaways.* Publish the boundary, not the guarantee. A fix needs the
   same adversarial pass as the thing it fixes.

**Notes for the write-up**
- Repo: github.com/mobius-style/mobius-browser-guard. Paper DOI: 10.5281/zenodo.21876300 — **published 2026-08-11**, https://zenodo.org/record/21876300 . Safe to cite in posts.
- Do not claim novelty of mechanism: CaMeL, the design-pattern catalogue and the
  dual-LLM pattern all occupy this position already. The contribution is the
  measurement of the coarse, post-hoc, installable version — and the failures.
- Keep every number traceable to `eval/results_policy_v0.3.1.json`. If a number can't be
  traced, cut it.
