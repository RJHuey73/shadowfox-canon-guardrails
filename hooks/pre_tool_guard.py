#!/usr/bin/env python3
"""
pre_tool_guard.py — Claude Code PreToolUse hook.

Fresh implementation of a described pattern (see repo README "Provenance"
section) — not a verified patch to unseen original source.

Reads the PreToolUse JSON payload on stdin, blocks (exit 2, reason on
stderr) or allows (exit 0) the pending tool call. Two independent checks:

  1. Bash-surface guard (the described original's own scope): destructive
     shell patterns, and named-surface protection for the Canon Spine base +
     both Supabase project refs when a write-shaped SQL keyword co-occurs.
     Extended here to also name the Active Task Queue and T0 Decision Log
     table IDs, per gap #1 from the 2026-09-03 session review.

  2. MCP tool-name guard (new — closes gap #4: the described original only
     covered Bash, but the highest-traffic write surfaces in this engagement
     were Airtable MCP calls and GitHub MCP pushes, neither of which are
     Bash). Matches write-shaped MCP tool names and, where the target is
     identifiable, requires a valid T0-GO marker before allowing the call
     through.

This hook's T0-GO check is READ-ONLY (does not mark the marker consumed) —
it's a fast, user-visible first line of defense. The MCP servers in mcp/ do
the authoritative, consuming check themselves via requireT0Go() in
lib/airtable-client.js, so gating still holds even on a session where this
hook isn't wired up. Keep the marker file format identical between the two
implementations (see README) — this file and lib/airtable-client.js are two
independent readers of the same on-disk contract, not one calling the other.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CANON_BASE_ID = "appVftexD3KJRcdij"

PROTECTED_TABLES = {
    "tbltw4Jy0LHWWz5DL": "Canon ID Registry",
    "tblEZ6ctzSoTBsfCW": "Session Ledger",
    "tblsVXX2XnhVLWMVE": "Active Task Queue",  # added, gap #1
    "tblX88U1VOwmK2fF5": "T0 Decision Log",  # added, gap #1
}

# Scopes that require a Tier 2 (governance-class) marker, not just Tier 1
# (operational). Two-tier markers adopted 2026-09-05 — see
# mcp/sfx-decisionlog-mcp.js header comment for why Decision Log specifically.
# A plain Tier 1 marker never satisfies these, even if scoped correctly.
TIER_2_SCOPES = {"tblX88U1VOwmK2fF5"}  # T0 Decision Log

# Per find_go_scope_for_mcp "kind" -> minimum tier required.
KIND_MIN_TIER = {"sfx_decisionlog": 2}

# Both Supabase project refs, as referenced in this session's own live
# Airtable queries (TQ-023/TQ-024 DROP SCHEMA records) — not invented here.
SUPABASE_REFS = {"mksmwqmphdkwwiyfesad", "oufyfdhjjvhrseythgrr"}

WRITE_KEYWORDS = re.compile(r"\b(DELETE|DROP|TRUNCATE|UPDATE|INSERT)\b", re.IGNORECASE)

DESTRUCTIVE_BASH_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),  # rm -rf, rm -fr, rm -Rf, ...
    re.compile(r"\bsudo\s+rm\b"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r">\s*/etc/"),
    re.compile(r">\s*/usr/"),
    re.compile(r"\bDROP\s+(TABLE|SCHEMA|DATABASE)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
]

# MCP tool-name patterns that indicate a write-capable call. Each entry is
# (regex, kind) where kind tells us how to find the target scope string.
MCP_WRITE_PATTERNS = [
    (re.compile(r"^mcp__Airtable__(create|update|delete)_"), "airtable_generic"),
    (re.compile(r"^mcp__github__(push_files|create_or_update_file|delete_file|merge_pull_request)$"), "github"),
    (re.compile(r"^mcp__Supabase__apply_migration$"), "supabase"),
    (re.compile(r"^mcp__sfx-session-mcp__(session_open|session_close)$"), "sfx_session"),
    (re.compile(r"^mcp__sfx-atq-mcp__(atq_create_task|atq_update_task)$"), "sfx_atq"),
    (re.compile(r"^mcp__sfx-decisionlog-mcp__decisionlog_create_entry$"), "sfx_decisionlog"),
]

GO_MARKER_PATH = Path(os.environ.get("T0_GO_MARKER_PATH", ".claude/t0-go.json"))


def block(reason: str) -> None:
    sys.stderr.write(reason + "\n")
    sys.exit(2)


def allow() -> None:
    sys.exit(0)


def check_bash(command: str) -> None:
    for pattern in DESTRUCTIVE_BASH_PATTERNS:
        if pattern.search(command):
            block(
                f"pre_tool_guard: blocked destructive Bash pattern ({pattern.pattern}) "
                f"in command: {command!r}"
            )

    if not WRITE_KEYWORDS.search(command):
        return

    # Scope must be a STABLE identifier a human can pre-mint a marker for —
    # never raw/truncated command text, which no marker could ever match.
    matched_scopes = set()
    for table_id in PROTECTED_TABLES:
        if table_id in command:
            matched_scopes.add(table_id)
    for ref in SUPABASE_REFS:
        if ref in command:
            matched_scopes.add(f"supabase:{ref}")
    if CANON_BASE_ID in command and not matched_scopes:
        # Base mentioned but no specific known table matched — still gate,
        # using the base ID itself as the scope a marker must cover.
        matched_scopes.add(CANON_BASE_ID)

    for scope in matched_scopes:
        min_tier = 2 if scope in TIER_2_SCOPES else 1
        check_t0_go(scope, min_tier=min_tier)


def find_go_scope_for_mcp(tool_name: str, tool_input: dict, kind: str):
    """Return the scope string requireT0Go should check, or None if the
    target can't be identified (in which case we fail closed anyway — an
    unidentifiable write-shaped call is exactly the case this exists for)."""
    if kind == "airtable_generic":
        base_id = tool_input.get("baseId")
        table_id = tool_input.get("tableId")
        if base_id == CANON_BASE_ID:
            return table_id or CANON_BASE_ID
        return None  # write to some other, non-Canon base — not this hook's concern
    if kind == "github":
        return "github:write"
    if kind == "supabase":
        return "supabase:apply_migration"
    if kind == "sfx_session":
        return "tblEZ6ctzSoTBsfCW"
    if kind == "sfx_atq":
        return "tblsVXX2XnhVLWMVE"
    if kind == "sfx_decisionlog":
        return "tblX88U1VOwmK2fF5"
    return None


def check_t0_go(scope: str, min_tier: int = 1) -> None:
    if not GO_MARKER_PATH.exists():
        block(
            f"pre_tool_guard: no T0-GO marker at {GO_MARKER_PATH} for scope "
            f"'{scope}' (requires Tier {min_tier}). Run hooks/issue_t0_go.py "
            f"(human-run only) first."
        )

    try:
        marker = json.loads(GO_MARKER_PATH.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        block(f"pre_tool_guard: T0-GO marker unreadable/malformed ({exc}) — treating as absent.")
        return

    if marker.get("consumed"):
        block(
            f"pre_tool_guard: T0-GO marker for decision {marker.get('decision_id')} "
            f"was already consumed. Issue a fresh one."
        )

    scope_list = marker.get("scope", [])
    if scope not in scope_list:
        block(
            f"pre_tool_guard: T0-GO marker for decision {marker.get('decision_id')} "
            f"does not cover '{scope}' (covers: {scope_list}). Issue a marker scoped to this write."
        )

    marker_tier = marker.get("tier", 1)
    if marker_tier < min_tier:
        block(
            f"pre_tool_guard: T0-GO marker for decision {marker.get('decision_id')} is "
            f"Tier {marker_tier}, but '{scope}' requires Tier {min_tier} (governance-class "
            f"write). Issue a Tier {min_tier} marker explicitly."
        )

    try:
        issued_at = datetime.fromisoformat(marker["issued_at"].replace("Z", "+00:00"))
        ttl = int(marker["ttl_seconds"])
    except (KeyError, ValueError, TypeError) as exc:
        block(f"pre_tool_guard: T0-GO marker has malformed issued_at/ttl_seconds ({exc}).")
        return

    now = datetime.now(timezone.utc)
    if (now - issued_at).total_seconds() > ttl:
        block(
            f"pre_tool_guard: T0-GO marker for decision {marker.get('decision_id')} "
            f"expired. Issue a fresh one."
        )
    # Valid — but NOT consumed here. The MCP server (or, for Bash/gh/Supabase
    # calls this hook alone gates, a human) is responsible for treating a
    # single marker as single-use where that matters. This hook's job is the
    # fast pre-check, not the source of truth on reuse.


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed input from the harness itself isn't this hook's failure
        # mode to enforce against — fail open rather than break every tool
        # call on a parsing bug.
        allow()
        return

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        check_bash(command)
        allow()
        return

    for pattern, kind in MCP_WRITE_PATTERNS:
        if pattern.match(tool_name):
            scope = find_go_scope_for_mcp(tool_name, tool_input, kind)
            if scope is not None:
                check_t0_go(scope, min_tier=KIND_MIN_TIER.get(kind, 1))
            allow()
            return

    allow()


if __name__ == "__main__":
    main()
