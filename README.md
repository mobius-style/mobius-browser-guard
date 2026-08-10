# mobius-browser-guard

A drop-in permission gate for **Claude in Chrome** browser tools, driven by an
**action ladder** instead of attack detection.

> **v0.3.0 fixes a critical hole introduced by v0.2.0's own fix.** The tab-origin
> map was learned by scanning any tool response, so a page could forge its own
> origin by printing a tab-context line in its body. If you installed v0.2.0,
> update. Details in [`eval/adversarial_review.md`](eval/adversarial_review.md).
>
> **Read [`POSITIONING.md`](POSITIONING.md) first.** This is an *auditable,
> bounded mediation layer*, not a safety guarantee. Its evaluation found that
> every one of 63 corpus attacker goals stays reachable inside the allow tier —
> mostly via reading, which is declared scope, but two genuine gaps remain. We
> publish that rather than hide it; see [`eval/`](eval/) for what holds and what
> does not.

Browser agents run inside your logged-in session. A malicious page can hide
instructions in its own text, and if the model follows them, the agent acts with
your cookies, your account, and your authority. The usual defence is to *detect*
the malicious text. Detection is useful and imperfect.

This gate takes the other half of the problem. It never reads the attack. It
classifies every browser tool call by **what the call can do** — read the page,
move a tab, type into a field, click a button, run arbitrary JavaScript — and
requires your confirmation before anything irreversible. An injection that slips
past every detector still cannot reach the send button without you.

That is the design intent. How far it actually holds — including the places it
does not — is measured in `eval/`, and the headline result there is a negative
one about this gate. Read it before relying on this.

```
model layer   :  Claude declines suspicious instructions        (detection — fallible)
action layer  :  guard.py judges the action class, not the text (containment — this repo)
```

## What it does

Verdicts are `allow` / `ask`, applied per tool call via a `PreToolUse` hook:

| Class | Tools | Default |
|---|---|---|
| Read-only (writes:0) | `read_page`, `get_page_text`, `find`, `read_console_messages`, `read_network_requests`, `tabs_context_mcp` | allow |
| Window & session (writes:1) | `tabs_create_mcp`, `tabs_close_mcp`, `resize_window`, `select_browser` | allow |
| Page write (writes:3) | `form_input`, `upload_image` | allow **only into a tab on an allowlisted host**; otherwise ask |
| Actuation (writes:4–5) | `computer` (click/type/key), `javascript_tool`, `file_upload`, `shortcuts_execute` | **ask** |
| Navigation | `navigate` | allow on allowlist (exact host, or an explicit `*.domain` entry) with a bounded post-host payload; else **ask** |
| Recording export | `gif_creator` | allow to record; **ask** to export onto a page or to disk |
| Unknown / unparseable | anything not in the ladder | **ask** (fail-closed) |

`computer` is split by its `action` field: `screenshot`, `scroll`, `zoom`, and
`hover` are reads; `left_click`, `type`, and `key` actuate the page.

### Writes are judged by where they land

A write tool is not safe or unsafe by its name. `form_input` typing into your
CRM is routine; `form_input` typing a session token into an `<input>` on the
page that just tried to hijack the agent is exfiltration, and no submit button
is involved. So the gate tracks which host each tab is on (from tool output, via
a PostToolUse hook) and allows writes only into tabs on allowlisted hosts.
Unknown tab, unknown origin, expired origin, or an origin learned by a different
session: fail closed. Only structural tools teach that map — never a read tool,
because a read returns attacker-authored text and v0.2.0 scraped it, which let a
page name its own tab as trusted. The same rule covers `upload_image`,
which can drag-and-drop a screenshot of an authenticated page onto any drop
target — a full-fidelity egress channel that looks nothing like one.

### The batch hole

`browser_batch` executes a list of tool calls in one round trip. A gate that
only looks at the outer call sees one benign-looking request and waves through
whatever is nested inside — read the page, *and also* run this JavaScript, *and
also* click here. `guard.py` recurses into every nested action and rules by the
worst class it finds. Any wrapper tool that composes other actions needs this
treatment; it is the first thing to check when adding a gate to any agent.

## Install

Requires Python 3 (standard library only) and Claude Code with the Claude in
Chrome extension connected.

```bash
git clone <this-repo> ~/mobius-browser-guard
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__claude-in-chrome__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 '/absolute/path/to/mobius-browser-guard/guard.py'",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp__claude-in-chrome__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 '/absolute/path/to/mobius-browser-guard/guard.py'",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Both entries run the same script; the PostToolUse one is how the guard learns
which host each tab is on, which is what lets it allow writes into your own
sites and stop them into a page the agent was not pointed at. Without it every
write falls back to `ask`, which is safe but noisy.

Open `/hooks` once (or restart) so the settings watcher picks it up. Verify it is
live by asking Claude to read any page, then checking `logs/decisions.jsonl`.

## Configure

Everything is in `policy.json`. Add the sites you actually work on to
`domain_allowlist`; loosen a tier by moving it from `ask` to `allow`. Two knobs
change the posture wholesale:

- `navigate_offlist_decision` — `ask` (default) or `allow` for open browsing
- `computer_act_decision` — `ask` (default); set to `allow` only for throwaway profiles
- `navigate_query_char_limit` — 256 by default; a navigation to an allowlisted
  host carrying more query/fragment than this is treated as egress and asks

Allowlist entries match the host **exactly**. Write `*.example.com` if you mean
subdomains too, and think before doing so on any domain where strangers can
register a subdomain (`*.github.io`, `*.vercel.app`, a multi-tenant SaaS) —
that hands an attacker an allowlisted origin.

Tightening is always safe. Loosening `javascript_tool` or `computer` is what the
gate exists to prevent, so do it deliberately.

## Demo

`demo/site/index.html` is a benign-looking community newsletter with an indirect
prompt injection buried in it, instructing any reading assistant to exfiltrate
cookies, navigate to a deletion page, and click through. Serve it and point the
agent at it:

```bash
python3 -m http.server 8781 --directory demo/site
```

`demo/evidence/containment_report.md` records the run: the three attack steps and
a batch-smuggled variant all stopped at `ask`, the two benign controls passed,
and no rule anywhere inspected the injected text.

## Evaluation — including where this gate fails

`eval/` holds a pre-registered evaluation (`FREEZE.md`, frozen before any data
was opened) run against 63 attacker goals from the InjecAgent corpus, plus an
adversarial review in which three independent reviewers were told to refute our
own findings.

The headline result is negative and it is about this gate: **all 63 goals have a
realization that stays inside the allow tier.** Most of that is reading, which
three reviewers unanimously judged to be declared scope rather than a defect;
strip it and two real gaps remain (a form that commits on input, on a site the
user allowlisted; and a short query string to an allowlisted host). Against
state-changing goals the ladder holds on the obvious routes — four of five
realizations of a representative attack are stopped. The same reviewers then
found four channels we had missed that were worse — screenshot-to-upload,
recording export, writing into the attacker's own DOM, and subdomain matching
that let one allowlist entry cover attacker-registrable hosts. Those are fixed
in v0.2.0. The headline number did not move.

Read `eval/RESULTS.md` for what the gate can still formally claim, and
`eval/adversarial_review.md` for what remains unfixed. If you are deciding
whether to rely on this, read those two files before the install instructions.

## Limits — read before trusting this

- **`ask` is only as strong as the human answering it.** A user who clicks
  through every prompt has no gate. Confirmation fatigue is the real failure mode
  and this repo does not solve it.
- **Single vendor, single surface.** Built and tested against the
  `mcp__claude-in-chrome__*` tool namespace. The approach generalizes; this code
  does not.
- **Tool namespaces change.** New tools fail closed to `ask`, which is the safe
  direction, but a renamed tool silently becomes "unknown" — re-check the ladder
  after extension updates.
- **Containment is not prevention.** A page can still trick the agent into
  reporting false information to you, and reads themselves can leak context. The
  ladder bounds *actions*, not *beliefs*.
- **The allow set is not effect-free, and that is the whole ballgame.** The
  guarantee is exactly as strong as the claim that nothing in the allow tier
  causes harm. Four counterexamples were found by adversarial review and fixed;
  the ones that remain are listed in `eval/adversarial_review.md`. Assume more
  exist.
- **Measured, narrowly.** The usability cost is measured on twelve author-written
  benign traces (0 prompts for reading, 1 per form submit). That is a weak
  positive, not a field study, and it says nothing about how a tired human
  answers the fifth prompt of the afternoon.

## Design note

The ladder comes from the RCGov governance layer used elsewhere in MOBIUS, where
every state-changing verb passes a three-valued gate before it writes. The claim
carried over here is narrow and testable: *containment that does not depend on
recognizing the attack degrades more gracefully than containment that does.*

After evaluation that claim needs a qualifier, and the qualified version is the
honest one: for any goal whose every realization requires an ask-class action, a
human decision is forced regardless of how the attack is phrased — but the
guarantee is exactly as strong as the claim that the allow set is effect-free,
which this gate does not enforce and which currently does not hold.

## License

MIT
