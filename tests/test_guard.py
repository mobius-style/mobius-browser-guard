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


CASES = [
    ("read is free",            P + "read_page",       {"tabId": 1}, "allow"),
    ("screenshot is a read",    P + "computer",        {"action": "screenshot", "tabId": 1}, "allow"),
    ("click actuates",          P + "computer",        {"action": "left_click", "coordinate": [1, 2], "tabId": 1}, "ask"),
    ("typing actuates",         P + "computer",        {"action": "type", "text": "x", "tabId": 1}, "ask"),
    ("arbitrary JS",            P + "javascript_tool", {"action": "javascript_exec", "text": "1", "tabId": 1}, "ask"),
    ("local file upload",       P + "file_upload",     {"tabId": 1}, "ask"),
    ("allowlisted host",        P + "navigate",        {"url": "https://example.com/a"}, "allow"),
    ("subdomain of allowlist",  P + "navigate",        {"url": "https://www.example.com/a"}, "allow"),
    ("lookalike is not a match", P + "navigate",       {"url": "https://notexample.com/a"}, "ask"),
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

if __name__ == "__main__":
    failed = 0
    for name, tool, tool_input, expected in CASES:
        got = verdict(tool, tool_input)
        ok = got == expected
        failed += not ok
        print("%-4s %-28s expected=%-5s got=%s" % ("PASS" if ok else "FAIL", name, expected, got))
    print("\n%d/%d passed" % (len(CASES) - failed, len(CASES)))
    sys.exit(1 if failed else 0)
