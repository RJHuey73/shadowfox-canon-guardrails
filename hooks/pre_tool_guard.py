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

# The marker contract is shared with mcp/lib/airtable-client.js and pinned by
# tests/fixtures/marker_cases.json, which both implementations run. Change
# the two readers and the fixtures together.
ISSUED_AT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6})?(?:Z|[+-]\d{2}:\d{2})$"
)
# A marker dated further ahead than this is refused: otherwise a future
# issued_at stretches its lifetime without bound.
MAX_CLOCK_SKEW_SECONDS = 60

# Returned by find_go_scope_for_mcp when the call targets the Canon base but
# its target identifiers are not usable strings.
MALFORMED_TARGET = object()


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
        check_t0_go(scope, min_tier=required_tier(scope))


def required_tier(scope: str, kind: str = "") -> int:
    """Minimum marker tier for a write. Derived from the scope as well as the
    tool kind, so the Decision Log needs Tier 2 whichever tool writes it."""
    return max(KIND_MIN_TIER.get(kind, 1), 2 if scope in TIER_2_SCOPES else 1)


def find_go_scope_for_mcp(tool_name: str, tool_input: dict, kind: str):
    """Return the scope string requireT0Go should check, or None if the
    target can't be identified (in which case we fail closed anyway — an
    unidentifiable write-shaped call is exactly the case this exists for)."""
    if kind == "airtable_generic":
        if "baseId" not in tool_input:
            return None  # e.g. create_base: no existing base is targeted
        base_id = tool_input["baseId"]
        if not isinstance(base_id, str):
            return MALFORMED_TARGET
        if base_id != CANON_BASE_ID:
            return None  # write to some other, non-Canon base — not this hook's concern
        table_id = tool_input.get("tableId")
        if table_id is None:
            return CANON_BASE_ID
        if not isinstance(table_id, str) or not table_id:
            return MALFORMED_TARGET
        return table_id
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


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def marker_problem(marker, scope: str, min_tier: int, now: datetime):
    """Why this marker does not authorize a write to `scope`, or None if it
    does. Same rules, in the same order, as requireT0Go() in
    mcp/lib/airtable-client.js."""
    if not isinstance(marker, dict):
        return "T0-GO marker is not a JSON object — treating as absent."
    decision = marker.get("decision_id")
    scopes = marker.get("scope")
    tier = marker.get("tier", 1)
    issued = marker.get("issued_at")
    ttl = marker.get("ttl_seconds")
    consumed = marker.get("consumed", False)
    if not isinstance(decision, str) or not decision:
        return "T0-GO marker has no decision_id — treating as absent."
    if not isinstance(scopes, list) or not scopes or not all(isinstance(x, str) and x for x in scopes):
        return f"T0-GO marker for decision {decision} has a malformed scope (must be a non-empty list of strings)."
    if not _is_int(tier) or tier not in (1, 2):
        return f"T0-GO marker for decision {decision} has a malformed tier ({tier!r}; must be 1 or 2)."
    if not isinstance(issued, str) or not ISSUED_AT_RE.match(issued):
        return f"T0-GO marker for decision {decision} has a malformed issued_at ({issued!r}; ISO-8601 with offset)."
    if not _is_int(ttl) or ttl <= 0:
        return f"T0-GO marker for decision {decision} has a malformed ttl_seconds ({ttl!r}; positive integer)."
    if not isinstance(consumed, bool):
        return f"T0-GO marker for decision {decision} has a malformed consumed flag ({consumed!r})."
    if consumed:
        return f"T0-GO marker for decision {decision} was already consumed. Issue a fresh one."
    if scope not in scopes:
        return (
            f"T0-GO marker for decision {decision} does not cover '{scope}' (covers: {scopes}). "
            f"Issue a marker scoped to this write."
        )
    if tier < min_tier:
        return (
            f"T0-GO marker for decision {decision} is Tier {tier}, but '{scope}' requires Tier "
            f"{min_tier} (governance-class write). Issue a Tier {min_tier} marker explicitly."
        )
    try:
        issued_at = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    except ValueError:
        return f"T0-GO marker for decision {decision} has an unparseable issued_at ({issued})."
    age = (now - issued_at).total_seconds()
    if age < -MAX_CLOCK_SKEW_SECONDS:
        return f"T0-GO marker for decision {decision} is dated in the future ({issued}). Re-issue it."
    if age > ttl:
        return f"T0-GO marker for decision {decision} expired. Issue a fresh one."
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
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        block(f"pre_tool_guard: T0-GO marker unreadable/malformed ({exc}) — treating as absent.")
        return

    problem = marker_problem(marker, scope, min_tier, datetime.now(timezone.utc))
    if problem:
        block(f"pre_tool_guard: {problem}")
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
    if not isinstance(payload, dict):
        allow()  # same harness-bug case as undecodable input, above
        return

    tool_name = payload.get("tool_name", "")
    if not isinstance(tool_name, str):
        allow()  # cannot name a guarded tool; same harness-bug case
        return
    tool_input = payload.get("tool_input", {}) or {}

    if tool_name == "Bash":
        if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command", ""), str):
            block("pre_tool_guard: malformed Bash tool_input — refusing to guess what it runs.")
        check_bash(tool_input.get("command", ""))
        allow()
        return

    for pattern, kind in MCP_WRITE_PATTERNS:
        if pattern.match(tool_name):
            if not isinstance(tool_input, dict):
                block(f"pre_tool_guard: malformed tool_input for write-capable tool {tool_name}.")
            scope = find_go_scope_for_mcp(tool_name, tool_input, kind)
            if scope is MALFORMED_TARGET:
                block(
                    f"pre_tool_guard: {tool_name} targets the Canon base with a malformed "
                    f"baseId/tableId — refusing to guess the target."
                )
            if scope is not None:
                check_t0_go(scope, min_tier=required_tier(scope, kind))
            allow()
            return

    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        # Claude Code treats a crash (exit 1) as non-blocking, i.e. it lets
        # the call through. An unexpected error here must block instead.
        block(f"pre_tool_guard: internal error ({type(exc).__name__}: {exc}) — blocking.")
