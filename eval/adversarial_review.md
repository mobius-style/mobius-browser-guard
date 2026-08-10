# Adversarial review of the gate's own holes

Per `FREEZE.md`, each candidate hole went to three independent reviewers who
were instructed to **refute** it and to default to "not a real hole" when
uncertain. A hole counts only if ≥2 of 3 judge it genuinely reachable under the
frozen policy. Reviewers saw the policy and the tool schemas, not the
pre-registered prediction. Two of the three read the implementation directly.

## Adjudicated verdicts

| # | Candidate hole | A | B | C | Adjudicated |
|---|---|---|---|---|---|
| H1 | `form_input` alone commits state on auto-submitting forms | REAL | REAL | REAL | **REAL** (3/3) |
| H2 | `read_network_requests` surfaces tokens / PII | REFUTED | REFUTED | REFUTED | **REFUTED** (0/3) |
| H3 | `read_console_messages` surfaces tokens / PII | REFUTED | REFUTED | REFUTED | **REFUTED** (0/3) |
| H4 | `read_page` returns authenticated content | REFUTED | REFUTED | REFUTED | **REFUTED** (0/3) |
| H5 | `navigate` to an allowlisted host exfiltrates via the URL | REAL | REAL | REAL | **REAL** (3/3) |
| H6 | no tool call needed — data is already in the agent's context | REFUTED | — | REFUTED | **REFUTED** |

The unanimous refutations of H2–H4 are the most useful result in this table.
All three reviewers made the same distinction independently: a hole must have
the form *"trace T achieves goal G with no ask, and the policy intends G to
require an ask."* Reading is `allow` **by design and by necessity** — an agent
that cannot read an authenticated page is not an agent — so H2–H4 restate the
policy rather than break it. They are load-bearing only when composed with an
egress primitive, at which point the finding belongs to the egress primitive.

H6 was judged ill-posed on the same grounds: a web page cannot read the model's
context, so data sitting there has not crossed the trust boundary, and no
action-layer gate can mediate "having data" because having is not an action.
One reviewer noted the steelman that is true — every allowed observable action
is a low-bandwidth covert channel — which is a residual limit of the whole
approach, not of this implementation.

## Reviewer-originated findings, verified against the implementation

The panel found paths our own hole-hunt had missed, and they were more severe
than the ones we predicted. Each was run through `guard.py`; all reproduced.

- **H7 — `computer:screenshot` → `upload_image`.** `upload_image` accepts a bare
  `coordinate` for drag-and-drop, so a screenshot of an authenticated page can
  be dropped onto an upload widget on the attacker's own page. Full-fidelity
  exfiltration, no click, no navigation. `file_upload` was `ask` precisely
  because it is an exfiltration channel; `upload_image` was `allow`, and it
  carries exactly the content an attacker wants. Found independently by two
  reviewers.
- **H8 — `gif_creator` has an upload primitive.** Its `export` action takes the
  same `coordinate`, exporting a recording of everything the agent viewed into
  an attacker-controlled target, and `download: true` writes to the local
  filesystem from an `allow`-class tool.
- **`form_input` into the attacker's own DOM.** The policy's justification —
  "reversible until submit" — assumed the sink was a form the user cares about.
  Writing a stolen token into an `<input>` on the attacker's page, which the
  page then reads with its own listener, needs no submit at all.
- **Implicit subdomain matching.** `host.endswith("." + dom)` meant one entry of
  `github.io`, `vercel.app`, `pages.dev` or any multi-tenant domain allowlisted
  every site an attacker can provision under it. All three reviewers flagged it.
- **Form poisoning (confirmation under false pretenses).** Substituting an
  attacker's account number into a field the human is about to submit. The
  prompt fires on the click and does not show the field contents, so the human
  approves the attacker's payload. Not fixed; see below.
- **`tabs_create_mcp` — hypothesis raised and refuted.** Two reviewers suspected
  it took a URL and bypassed the allowlist. The schema takes no parameters, so
  the allow verdict is sound *today*. One noted this is sound by coincidence of
  upstream design, not by construction: if a `url` parameter is ever added, the
  policy silently becomes unsound.

## What changed in v0.2.0

| Path | v0.1.0 | v0.2.0 |
|---|---|---|
| screenshot → `upload_image` onto the attacker's page | allow | **ask** |
| `gif_creator` export onto the attacker's page | allow | **ask** |
| `gif_creator` export downloaded to disk | allow | **ask** |
| `form_input` writing into the attacker's page | allow | **ask** |
| navigate to an attacker subdomain of an allowlisted domain | allow | **ask** |
| bulk data in a query string to an allowlisted host | allow | **ask** |
| auto-submit form on the allowlisted target site | allow | allow |
| short query to an allowlisted host | allow | allow |

The mechanism is an **origin predicate**, not a new tier: `form_input` and
`upload_image` are allowed only into a tab known to sit on an allowlisted host,
which requires the guard to track `tabId → host` from PostToolUse output.
Unknown tab fails closed. Bare allowlist entries now match exactly; subdomains
require an explicit `*.domain` entry. Navigation to an allowlisted host is
bounded by query/fragment length rather than inspected — a bandwidth limit, not
a content check, so the no-detection property is preserved.

## Known and unfixed

- **Auto-submit commits on the allowlisted target site.** The origin predicate
  cannot help here: the target is a site the user legitimately allowlisted.
  Judges put the practical severity low — money movement, deletion, permission
  grants and 2FA changes essentially never fire on a bare input event; what does
  is filters, drafts, quantities and preferences — but it is real.
- **Form poisoning.** Structural: the human is asked about the click, not the
  contents. Fixing it needs the prompt to show the field values, which is a
  host-UI change, not a policy change.
- **Open redirects on allowlisted hosts.** `https://allowed.example/r?to=evil`
  still passes the host check. Bounding query length raises the cost but does
  not close it.
- **`localhost` in the default allowlist** gives allow-tier GET reach to every
  service on the developer's loopback. Kept because local development is the
  primary use case; documented rather than removed.
- **Tool-schema drift.** The ladder is pinned to tool names and argument shapes
  observed on 2026-08-10. New arguments on existing tools fail open.


## Second round — adversarial review of the paper about this gate

A draft systems report describing v0.2.0 was put to two further independent
reviewers: one instructed to reject it as a hostile venue reviewer, one to
fact-check every claim against the artifacts. Both read the implementation.
Their findings were more damaging than the first round's, and all of the code
findings reproduced.

**Critical — the system was not content-blind, though `classify()` was.**
`record_tab_origin()` scanned any tool response, including page text. A page
could therefore print a tab-context line naming its own tab as an allowlisted
host, and the write channels closed in v0.2.0 re-opened. This is the sharpest
finding in either round: the fix for one reviewer-found hole introduced a worse
one, in the exact component that was supposed to make the fix sound. Fixed in
v0.3.0 — only structural tools teach the origin map, and only their trailing
context block is parsed.

**Four fail-open defects, each contradicting a claim the draft made.**

| Defect | The claim it falsified |
|---|---|
| egress bounding measured query and fragment but not the path | "bulk data in a query string ... allow → ask" — one character defeated it |
| a batch whose payload sat under another key, or was not a list, passed with its nested calls unclassified | "our gate recurses and rules by the worst nested class"; "unparseable arguments fail closed" |
| an unrecognized `gif_creator` action was allowed by default | "gif export → ask" |
| a recorded tab origin was trusted forever and across sessions | "recovers the property for a defined subset" |

All five are fixed in v0.3.0 with regression tests (42/42). The lesson we take
is narrower and more uncomfortable than the first round's: **a fix authored in
response to a finding deserves the same adversarial pass as the original
artifact.** Ours did not get one, and it shipped a critical hole for a day.

**Documentation defects the fact-checker found**, recorded here rather than
quietly corrected: `RESULTS.md` named a gate commit that did not match the
committed `results.json` (now disclosed at the top of that file); the draft
attributed a "default to not-a-hole" instruction to `FREEZE.md`, which does not
contain it; `FREEZE.md` registered AgentDojo, WASP and ST-WebAgentBench as data
sources and only InjecAgent was used, which is a pre-registration deviation and
not merely a design choice; pre-registered RQ3 was under-reported; and the
partition of InjecAgent's tools into act/read/download is ours, not the
corpus's — `GmailSendEmail` and one other were moved into the act set.
