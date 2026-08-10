#!/usr/bin/env python3
"""mobius-browser-guard — RCGov-style action-ladder gate for Claude in Chrome.

Claude Code hook. On PreToolUse it classifies the browser tool call against
policy.json and returns allow / ask. On PostToolUse it records which host each
tab is on, so that write-class calls can be judged by the origin they write to.

Design rule: containment must not depend on detecting an attack. Every call is
judged by its action class, its target host, and the origin of the tab it acts
on — never by whether its content looks malicious. Unknown tools, unknown tabs
and unparseable batches fail closed.

v0.2.0 closes four allow-tier egress channels found by adversarial review:
screenshot->upload_image, gif_creator export-to-page, form_input into a
non-allowlisted (i.e. possibly attacker-owned) page, and implicit subdomain
matching that let one allowlist entry cover attacker-registrable hosts.
"""
import datetime
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "mcp__claude-in-chrome__"
SEVERITY = {"allow": 0, "ask": 1, "deny": 2}
TABS_PATH = os.path.join(BASE, "logs", "tab_origins.json")


def load_policy():
    with open(os.path.join(BASE, "policy.json"), encoding="utf-8") as f:
        return json.load(f)


def host_of(url):
    return re.sub(r"^[a-z]+://", "", str(url)).split("/")[0].split(":")[0].lower()


def host_allowed(policy, host):
    """Exact match, or an explicit "*.domain" wildcard entry.

    Bare entries no longer match subdomains. One entry of github.io used to
    allowlist every attacker-registrable site under it.
    """
    for dom in policy["domain_allowlist"]:
        d = dom.lower()
        if d.startswith("*."):
            base = d[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == d:
            return True
    return False


def load_tabs():
    try:
        with open(TABS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def tab_host(tab_id):
    return load_tabs().get(str(tab_id))


def writes_to_trusted_tab(policy, tool_input):
    """Is this write aimed at a tab we know to be on an allowlisted host?

    Unknown tab -> False (fail closed). This is what stops a write into a page
    the agent was not pointed at — including the attacker's own page, which is
    where an injection arrives from.
    """
    tid = tool_input.get("tabId")
    if tid is None:
        return False
    host = tab_host(tid)
    return bool(host) and host_allowed(policy, host)


def classify(policy, key, tool_input):
    """Return (decision, reason) for one tool call, recursing into batches."""
    if key == "browser_batch":
        worst = ("allow", "batch: empty")
        actions = tool_input.get("actions") or []
        if not isinstance(actions, list):
            return ("ask", "batch: unparseable actions (fail-closed)")
        for item in actions:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                return ("ask", "batch: unparseable item (fail-closed)")
            d, r = classify(policy, item["name"], item.get("input") or {})
            if SEVERITY.get(d, 1) > SEVERITY.get(worst[0], 0):
                worst = (d, "batch[%s]: %s" % (item["name"], r))
        if worst[0] == "allow" and actions:
            worst = ("allow", "batch: all %d items allowed" % len(actions))
        return worst

    if key == "computer":
        act = tool_input.get("action", "")
        if act in policy["computer_read_actions"]:
            return ("allow", "computer:%s is read-only" % act)
        return (policy["computer_act_decision"], "computer:%s actuates the page" % (act or "?"))

    if key == "navigate":
        url = str(tool_input.get("url", ""))
        if url in ("back", "forward"):
            return ("allow", "history navigation")
        host = host_of(url)
        if not host_allowed(policy, host):
            return (policy["navigate_offlist_decision"], "navigate: %s not on allowlist" % host)
        # An allowlisted host is still an egress channel: everything after the
        # path can carry data out. Bound the payload rather than read it.
        tail = url.split("?", 1)[1] if "?" in url else ""
        frag = url.split("#", 1)[1] if "#" in url else ""
        payload = len(tail) + len(frag)
        limit = policy.get("navigate_query_char_limit", 0)
        if limit and payload > limit:
            return ("ask", "navigate: %s allowlisted but carries %d chars of query/fragment "
                           "(limit %d) — possible egress" % (host, payload, limit))
        return ("allow", "navigate: %s on allowlist" % host)

    if key == "gif_creator":
        act = tool_input.get("action", "")
        if act == "export" and ("coordinate" in tool_input or tool_input.get("download")):
            return ("ask", "gif_creator:export sends a session recording to a page "
                           "or to disk (writes:4)")
        return ("allow", "gif_creator:%s is local recording control (writes:1)" % (act or "?"))

    if key in ("form_input", "upload_image"):
        tier = policy["tiers"][key]
        if tier["decision"] != "allow":
            return (tier["decision"], tier["reason"])
        if writes_to_trusted_tab(policy, tool_input):
            return ("allow", "%s into a tab on an allowlisted host" % key)
        tid = tool_input.get("tabId")
        where = tab_host(tid) or "unknown origin"
        return ("ask", "%s writes into a tab on %s — not an allowlisted host, so the "
                       "sink may be attacker-controlled" % (key, where))

    tier = policy["tiers"].get(key)
    if tier is None:
        return ("ask", "unknown tool %r (fail-closed)" % key)
    return (tier["decision"], tier["reason"])


def record_tab_origin(event):
    """PostToolUse: remember which host each tab is on.

    Parses the tab context that Chrome tools append to their output. Best
    effort — a tab we fail to learn about stays unknown, and unknown fails
    closed at classify() time.
    """
    resp = event.get("tool_response") or ""
    text = resp if isinstance(resp, str) else json.dumps(resp)
    text = text.replace('\\"', '"')       # survive a JSON-encoded response
    tabs = load_tabs()
    # "• tabId 123: "Title" ("https://host/path")" — the context block the
    # Chrome tools append to their output.
    for tid, url in re.findall(r'tabId (\d+):[^(\n]*\("([^"]+)"\)', text):
        tabs[tid] = host_of(url)
    # {"tabId": 123, "title": "...", "url": "https://host/path"}
    for tid, url in re.findall(r'"tabId"\s*:\s*(\d+).{0,200}?"url"\s*:\s*"([^"]+)"', text, re.S):
        tabs[tid] = host_of(url)
    try:
        os.makedirs(os.path.dirname(TABS_PATH), exist_ok=True)
        with open(TABS_PATH, "w", encoding="utf-8") as f:
            json.dump(tabs, f)
    except Exception:
        pass


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # not for us / malformed: stay out of the way

    tool_name = event.get("tool_name", "")
    if not tool_name.startswith(PREFIX):
        sys.exit(0)  # non-browser tool: no opinion

    if event.get("hook_event_name") == "PostToolUse" or "tool_response" in event:
        record_tab_origin(event)
        sys.exit(0)

    try:
        policy = load_policy()
        decision, reason = classify(policy, tool_name[len(PREFIX):], event.get("tool_input") or {})
    except Exception as exc:  # gate must fail closed, not open
        decision, reason = "ask", "guard error (fail-closed): %s" % exc

    try:
        with open(os.path.join(BASE, "logs", "decisions.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                "session": event.get("session_id"),
                "tool": tool_name,
                "decision": decision,
                "reason": reason,
                "input_chars": len(json.dumps(event.get("tool_input") or {})),
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass  # logging failure must not change the decision

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": "[browser-guard] " + reason,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
