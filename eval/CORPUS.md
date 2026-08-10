# Corpus provenance

## Used

**InjecAgent** — indirect prompt injection against tool-integrated agents.
1,054 static test cases (510 direct-harm, 544 data-stealing) naming 63 distinct
attacker tools. MIT licensed (verified via the GitHub license API on
2026-08-10). Source: https://github.com/uiuc-kang-lab/InjecAgent

Only the data files are read; the repository's harness is never executed. The
four files fetched were:

```
data/test_cases_dh_base.json     672,918 B
data/test_cases_ds_base.json     765,370 B
data/attacker_cases_dh.jsonl      10,937 B
data/attacker_cases_ds.jsonl      13,209 B
```

To reproduce, fetch those four from the repository's `main` branch and run
`build_mapping.py` then `run_eval.py`. The eval itself needs no corpus file at
run time — the 63 attacker tool names are baked into `build_mapping.py`, so the
harness is deterministic and offline. The corpus is what justifies that list
being the right one, not an input to the computation.

## Considered and not used

**AgentDojo** (MIT, https://github.com/ethz-spylab/agentdojo) — 629 injection
cases over banking, Slack, travel and workspace suites. Its attacker goals are
API-tool calls of the same shape as InjecAgent's, so adding it would multiply
case count without adding a new *action class*, which is the unit this eval
counts. Listed here so the omission is a stated choice, not an oversight.

**WASP** and **ST-WebAgentBench** — genuinely browser-flavoured attacker goals,
but welded to VisualWebArena / WebArena Docker stacks. Not executed. Their value
here would be realism, and the honest position is that this eval lacks that
realism rather than that it borrowed it. See the limitations in `RESULTS.md`.

## The skew this leaves

InjecAgent's attacker tools are API-style (`BankManagerTransferFunds`,
`GmailSendEmail`). A Chrome agent does not call those; it clicks a button on a
bank's website. The mapping in `mapping.json` bridges that gap and is
author-constructed, which is exactly why block-rate over the mapping is not
reported as the headline result. What the corpus contributes is a defensible,
externally-sourced enumeration of *what attackers actually try to accomplish* —
63 goals we did not choose — so that the reachability analysis is run against
someone else's threat list rather than our own imagination.
