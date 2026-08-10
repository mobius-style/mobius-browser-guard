# mobius-browser-guard

A drop-in permission gate for **Claude in Chrome** browser tools, driven by an
**action ladder** instead of attack detection.

Browser agents run inside your logged-in session. A malicious page can hide
instructions in its own text, and if the model follows them, the agent acts with
your cookies, your account, and your authority. The usual defence is to *detect*
the malicious text. Detection is useful and imperfect.

This gate takes the other half of the problem. It never reads the attack. It
classifies every browser tool call by **what the call can do** — read the page,
move a tab, type into a field, click a button, run arbitrary JavaScript — and
requires your confirmation before anything irreversible. An injection that slips
past every detector still cannot reach the send button without you.

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
| Page write (writes:3) | `form_input`, `upload_image` | allow + logged |
| Actuation (writes:4–5) | `computer` (click/type/key), `javascript_tool`, `file_upload`, `shortcuts_execute` | **ask** |
| Navigation | `navigate` | allow on allowlist, else **ask** |
| Unknown / unparseable | anything not in the ladder | **ask** (fail-closed) |

`computer` is split by its `action` field: `screenshot`, `scroll`, `zoom`, and
`hover` are reads; `left_click`, `type`, and `key` actuate the page.

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
    ]
  }
}
```

Open `/hooks` once (or restart) so the settings watcher picks it up. Verify it is
live by asking Claude to read any page, then checking `logs/decisions.jsonl`.

## Configure

Everything is in `policy.json`. Add the sites you actually work on to
`domain_allowlist`; loosen a tier by moving it from `ask` to `allow`. Two knobs
change the posture wholesale:

- `navigate_offlist_decision` — `ask` (default) or `allow` for open browsing
- `computer_act_decision` — `ask` (default); set to `allow` only for throwaway profiles

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
- **Not yet measured.** The demo is an existence proof, not a benchmark. Blocking
  rate against a real injection corpus, and the usability cost of the `ask`
  prompts on real tasks, are unmeasured — that work is next, and the honest
  result may be that the cost is too high.

## Design note

The ladder comes from the RCGov governance layer used elsewhere in MOBIUS, where
every state-changing verb passes a three-valued gate before it writes. The claim
carried over here is narrow and testable: *containment that does not depend on
recognizing the attack degrades more gracefully than containment that does.*

## License

MIT
