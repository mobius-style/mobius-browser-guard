# LinkedIn — final, ready to paste

**Attach:** `outreach/figure_hero.png` (2360×2000)
**Paste the text below the line, exactly as-is.** Every number is traceable to
`eval/results_policy_v0.3.1.json` or to a re-run verdict from `guard.py`.

---

We built a security layer for AI browser agents, then published the proof that
it doesn't fully work. Here's why that was the right call.

An AI agent that drives your browser inherits everything your browser has: your
logged-in sessions, your cookies, your authority. A malicious page can hide
instructions in its own text, and if the agent follows them, it acts as you. The
usual defence is to detect the malicious text — useful, and never complete,
because an attacker can always rephrase.

So we built the other half: a gate that never reads the attack at all. It
classifies each browser action by what it can do — read a page, click a button,
run code — and requires human approval before anything irreversible.

Then we measured it against 63 attacker goals from a published corpus, and asked
the question we least wanted answered: can any goal be reached without ever
triggering a prompt?

Yes. Three patterns get through, and between them they cover all 63.

Two of those three turned out not to be flaws. Independent reviewers, instructed
to refute us, unanimously ruled that reading an authenticated page is what a
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
same class as the one it closed. That is the lesson worth passing on: a fix
needs the same adversarial review as the thing it fixes. Ours didn't get one,
and shipped a critical hole for a day.

The gate is MIT-licensed and installs in about ten minutes. On sites you've
allowlisted it asks for nothing until you commit a change; 85.7% of ordinary
calls proceed silently. Its residual attack surface is published alongside it,
because a security tool that only reports what it survived isn't evidence.

Paper: https://doi.org/10.5281/zenodo.21876300
Code: https://github.com/mobius-style/mobius-browser-guard

#AISecurity #PromptInjection #AIAgents #AppSec
