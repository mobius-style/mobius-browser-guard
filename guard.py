#!/usr/bin/env python3
"""mobius-browser-guard — RCGov-style action-ladder gate for Claude in Chrome tools.

Claude Code PreToolUse hook. Reads the hook event on stdin, classifies the
browser tool call against policy.json, and returns allow / ask / deny.

Design rule: containment must not depend on detecting an attack. Every
call is judged by its action class (what it can do), never by whether its
content looks malicious. Unknown tools and unparseable batches fail closed.
"""
import datetime
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
PREFIX = "mcp__claude-in-chrome__"
SEVERITY = {"allow": 0, "ask": 1, "deny": 2}


def load_policy():
    with open(os.path.join(BASE, "policy.json"), encoding="utf-8") as f:
        return json.load(f)


def host_of(url):
    return re.sub(r"^[a-z]+://", "", str(url)).split("/")[0].split(":")[0].lower()


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
        for dom in policy["domain_allowlist"]:
            if host == dom or host.endswith("." + dom):
                return ("allow", "navigate: %s on allowlist" % host)
        return (policy["navigate_offlist_decision"], "navigate: %s not on allowlist" % host)

    tier = policy["tiers"].get(key)
    if tier is None:
        return ("ask", "unknown tool %r (fail-closed)" % key)
    return (tier["decision"], tier["reason"])


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # not for us / malformed: stay out of the way

    tool_name = event.get("tool_name", "")
    if not tool_name.startswith(PREFIX):
        sys.exit(0)  # non-browser tool: no opinion

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
