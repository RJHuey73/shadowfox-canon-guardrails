#!/usr/bin/env python3
"""
pre_tool_guard.py — Claude Code PreToolUse hook.

Fresh implementation of a described pattern (see repo README "Provenance"
section) — not a verified patch to unseen original source.

Reads the PreToolUse JSON payload on stdin, blocks (exit 2, reason on
stderr) or allows (exit 0) the pending tool call. Input it cannot decode, or
that does not name a tool, is blocked: this hook fails closed (T12).
Three independent checks:

  1. Bash-surface guard (the described original's own scope): destructive
     shell patterns, and named-surface protection for the Canon Spine base +
     both Supabase project refs when a write-shaped SQL keyword or HTTP write
     co-occurs. Also blocks any command that names the T0-GO marker or runs
     the issuer (T10, partial).

  2. File-tool guard: Write/Edit/MultiEdit/NotebookEdit aimed at the marker
     path is blocked (T10, partial).

  3. MCP guard, deny by default inside each governed namespace (Airtable,
     Supabase, Notion, GitHub, sfx-* servers): a tool passes without a marker
     only if it is a known read. Every other tool in the namespace, including
     tools a server adds later, needs a valid T0-GO marker (T11).

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

# An HTTP request that writes: an explicit write method, a request body, or a
# write call in an inline script. Only gates commands that also name a
# protected identifier (see check_bash), so a match alone blocks nothing.
HTTP_WRITE_RE = re.compile(
    r"(?:-X|--request|--method)\s*=?\s*['\"]?(?:POST|PUT|PATCH|DELETE)\b"
    r"|(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode|-ascii)?|--json|--form)(?:[\s=]|$)"
    r"|\b(?:requests|httpx|session|client)\.(?:post|put|patch|delete)\s*\("
    r"|\bmethod\s*[:=]\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]",
    re.IGNORECASE,
)
NOTION_API_HOST = "api.notion.com"

# --- MCP namespaces (T11) ----------------------------------------------------
# An MCP tool is mcp__<server>__<tool>. A server whose name contains one of
# these keywords is governed, whatever prefix a plugin wraps it in (e.g.
# mcp__plugin_airtable_airtable__*). config/settings.json.example routes the
# same keywords to this hook; tests check the two agree.
GOVERNED_SERVER_KEYWORDS = {
    "airtable": ("airtable", "Airtable", "AIRTABLE"),
    "supabase": ("supabase", "Supabase", "SUPABASE"),
    "notion": ("notion", "Notion", "NOTION"),
    "github": ("github", "GitHub", "Github", "GITHUB"),
    "sfx": ("sfx-",),
}

# Reads pass without a marker. Anything not listed here is treated as a write.
READ_PREFIX = re.compile(r"^(?:get|list|search|describe)_")
EXTRA_READS = {
    "airtable": {"ping", "analyze_table", "display_records_for_table", "fetch_automation_input_data"},
    "supabase": {"query_logs", "generate_typescript_types"},
    "github": set(),
}
NOTION_READ = re.compile(
    r"^notion-(?:fetch|search|get|list|query|view|download|read|wait|memory-search)(?:-|$)"
)

# This repo's own servers: scope each write must be covered for, minimum tier,
# and the tools that only read. Must match mcp/*.js and config/mcp.json.example.
SFX_SERVERS = {
    "sfx-canon-mcp": (
        "tbltw4Jy0LHWWz5DL", 1,
        {"canon_get_clusters", "canon_get_latest_entry", "canon_get_next_id",
         "canon_get_session_ledger", "canon_query_entry"},
    ),
    "sfx-session-mcp": ("tblEZ6ctzSoTBsfCW", 1, {"session_get"}),
    "sfx-atq-mcp": ("tblsVXX2XnhVLWMVE", 1, {"atq_get_item", "atq_list_open"}),
    "sfx-decisionlog-mcp": ("tblX88U1VOwmK2fF5", 2, {"decisionlog_get_latest", "decisionlog_search"}),
}

# File tools and the input field that names the file they write.
FILE_WRITE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
                    "NotebookEdit": "notebook_path"}

GO_MARKER_PATH = Path(os.environ.get("T0_GO_MARKER_PATH", ".claude/t0-go.json"))
DEFAULT_MARKER_NAME = "t0-go.json"
ISSUER_NAME = "issue_t0_go"

# Upper bound on a marker's lifetime. Enforced by the issuer and by both
# readers; mirrored as MAX_TTL_SECONDS in hooks/issue_t0_go.py and
# mcp/lib/airtable-client.js, and pinned by tests/fixtures/marker_cases.json.
MAX_TTL_SECONDS = 3600

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


def marker_tokens() -> set:
    """Strings whose presence in a Bash command means it touches the marker
    or the issuer. A custom T0_GO_MARKER_PATH is matched by its full path
    only: a bare custom basename could be any common filename."""
    tokens = {DEFAULT_MARKER_NAME, ISSUER_NAME}
    if GO_MARKER_PATH.name != DEFAULT_MARKER_NAME:
        tokens.add(str(GO_MARKER_PATH))
    return {t.lower() for t in tokens}


def check_bash(command: str) -> None:
    for pattern in DESTRUCTIVE_BASH_PATTERNS:
        if pattern.search(command):
            block(
                f"pre_tool_guard: blocked destructive Bash pattern ({pattern.pattern}) "
                f"in command: {command!r}"
            )

    # T10 (partial): the agent must not mint its own authorization. Any
    # command naming the marker or the issuer is refused, reads included.
    # Obfuscated paths still get through; see test_known_gaps.py.
    # Case-insensitive: macOS filesystems usually are, so T0-GO.JSON is the
    # same file.
    lowered = command.lower()
    for token in sorted(marker_tokens()):
        if token in lowered:
            block(
                f"pre_tool_guard: Bash command references '{token}'. Markers are minted by "
                f"a human outside the agent session (hooks/issue_t0_go.py in your own terminal)."
            )

    http_write = HTTP_WRITE_RE.search(command)
    if not (WRITE_KEYWORDS.search(command) or http_write):
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
    if http_write and NOTION_API_HOST in command:
        matched_scopes.add("notion:write")

    for scope in sorted(matched_scopes):
        check_t0_go(scope, min_tier=required_tier(scope))


def check_file_write(tool_name: str, tool_input) -> None:
    """T10 (partial): file tools must not write the marker, its lock file, or
    anything resolving to the marker path."""
    if not isinstance(tool_input, dict):
        block(f"pre_tool_guard: malformed tool_input for {tool_name}.")
    path = tool_input.get(FILE_WRITE_TOOLS[tool_name])
    if not isinstance(path, str) or not path:
        block(f"pre_tool_guard: {tool_name} has no usable target path — refusing to guess.")
    # Names compare case-insensitively (macOS filesystems usually are). A
    # custom marker path is matched by resolved path, never by its basename.
    name = Path(path).name.lower()
    hits_name = name == DEFAULT_MARKER_NAME or name.startswith(DEFAULT_MARKER_NAME + ".")
    resolved = os.path.normcase(os.path.realpath(path))
    marker = os.path.normcase(os.path.realpath(GO_MARKER_PATH))
    hits_path = resolved.lower() in (marker.lower(), marker.lower() + ".lock")
    if hits_name or hits_path:
        block(
            f"pre_tool_guard: {tool_name} targets the T0-GO marker ({path}). Markers are "
            f"minted by a human outside the agent session."
        )


def required_tier(scope: str, server_min_tier: int = 1) -> int:
    """Minimum marker tier for a write. Derived from the scope as well as the
    server, so the Decision Log needs Tier 2 whichever tool writes it."""
    return max(server_min_tier, 2 if scope in TIER_2_SCOPES else 1)


def mcp_parts(tool_name: str):
    """(server, tool) for mcp__<server>__<tool>, else None."""
    if not tool_name.startswith("mcp__"):
        return None
    server, sep, tool = tool_name[len("mcp__"):].partition("__")
    if not sep or not server or not tool:
        return None
    return server, tool


def governed_namespace(tool_name: str):
    """The governed namespace a tool belongs to, or None. A tool name that
    mentions a governed keyword but cannot be parsed returns 'unparseable'."""
    parts = mcp_parts(tool_name)
    target = parts[0] if parts else tool_name
    for namespace, keywords in GOVERNED_SERVER_KEYWORDS.items():
        if any(k in target for k in keywords):
            if parts is None:
                return "unparseable" if tool_name.startswith("mcp__") else None
            return namespace
    return None


def is_read(namespace: str, server: str, tool: str) -> bool:
    if namespace == "sfx":
        return server in SFX_SERVERS and tool in SFX_SERVERS[server][2]
    if namespace == "notion":
        return bool(NOTION_READ.match(tool))
    return bool(READ_PREFIX.match(tool)) or tool in EXTRA_READS.get(namespace, set())


def airtable_scope(tool_input: dict):
    """Scope for an Airtable write, None if it is not aimed at the Canon base,
    or MALFORMED_TARGET if its target identifiers are not usable strings."""
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


def write_scope(namespace: str, server: str, tool: str, tool_input: dict):
    """(scope, min tier) a marker must cover for this write. scope is None
    when the write is outside this hook's concern."""
    if namespace == "airtable":
        scope = airtable_scope(tool_input)
    elif namespace == "supabase":
        scope = f"supabase:{tool}"
    elif namespace == "notion":
        scope = "notion:write"
    elif namespace == "github":
        scope = "github:write"
    else:  # sfx: an unknown sfx server is gated on the whole Canon base
        scope, server_tier, _ = SFX_SERVERS.get(server, (CANON_BASE_ID, 1, set()))
        return scope, required_tier(scope, server_tier)
    if scope is None or scope is MALFORMED_TARGET:
        return scope, 1
    return scope, required_tier(scope)


def check_governed_mcp(namespace: str, tool_name: str, tool_input) -> None:
    if namespace == "unparseable":
        block(f"pre_tool_guard: cannot parse governed MCP tool name {tool_name!r} — refusing to guess.")
    server, tool = mcp_parts(tool_name)
    if is_read(namespace, server, tool):
        return
    if not isinstance(tool_input, dict):
        block(f"pre_tool_guard: malformed tool_input for write-capable tool {tool_name}.")
    scope, min_tier = write_scope(namespace, server, tool, tool_input)
    if scope is MALFORMED_TARGET:
        block(
            f"pre_tool_guard: {tool_name} targets the Canon base with a malformed "
            f"baseId/tableId — refusing to guess the target."
        )
    if scope is not None:
        check_t0_go(scope, min_tier=min_tier)


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
    if ttl > MAX_TTL_SECONDS:
        return (
            f"T0-GO marker for decision {decision} has ttl_seconds {ttl}, above the "
            f"{MAX_TTL_SECONDS}s maximum. Re-issue it."
        )
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
    # T12: this hook is only invoked for tools its matchers route to it, so
    # input it cannot read is never a reason to let the call through. A
    # harness bug here blocks routed calls until it is fixed.
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        block("pre_tool_guard: undecodable hook input — blocking (fail closed).")
    if not isinstance(payload, dict):
        block("pre_tool_guard: hook input is not a JSON object — blocking (fail closed).")

    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name:
        block("pre_tool_guard: hook input names no tool — blocking (fail closed).")
    tool_input = payload.get("tool_input", {}) or {}

    if tool_name == "Bash":
        if not isinstance(tool_input, dict) or not isinstance(tool_input.get("command", ""), str):
            block("pre_tool_guard: malformed Bash tool_input — refusing to guess what it runs.")
        check_bash(tool_input.get("command", ""))
        allow()

    if tool_name in FILE_WRITE_TOOLS:
        check_file_write(tool_name, tool_input)
        allow()

    namespace = governed_namespace(tool_name)
    if namespace is not None:
        check_governed_mcp(namespace, tool_name, tool_input)
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
