#!/usr/bin/env python3
"""
pre_tool_guard.py — Claude Code PreToolUse hook (local input/policy hardening).

Fresh implementation of a described pattern (see repo README "Provenance"
section) — not a verified patch to unseen original source.

Contract: read one PreToolUse JSON payload on stdin; exit 0 to allow, exit 2
to deny with an actionable diagnostic on stderr. Every other outcome is also
exit 2: malformed input, structurally invalid input, an unreadable or
malformed marker, and any internal error. (Claude Code treats exit 1 as a
NON-blocking error, so this file never lets an uncaught exception escape.)

Policy (adopted for this hardening pass; see README "Operation policy"):

  * Explicitly classified READ-ONLY MCP operations are allowed.
  * Explicitly classified PROTECTED operations require a valid T0-GO marker
    scoped to the operation (this hook only checks the marker; it never
    consumes it — the MCP servers do the authoritative consuming check).
  * Every other MCP operation is DENIED pending classification. To classify
    one, edit READ_ONLY_RULES or PROTECTED_RULES below (a reviewed change).
  * Bash: destructive patterns, writes to named Canon/Supabase surfaces, and
    commands that touch the T0-GO marker or its issuer are checked. These
    shell-pattern checks are best-effort and are NOT an authorization
    boundary (see README "Known uncovered routes").
  * File-write tools (Write/Edit/MultiEdit/NotebookEdit) are denied when the
    target is the T0-GO marker. Other built-in (non-MCP) tools are outside
    this policy and are allowed.

This is local input/policy hardening. It does not close G1: the marker is
still a local file, and an agent that holds a write credential can reach the
protected surface by routes this hook does not see.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

CANON_BASE_ID = "appVftexD3KJRcdij"

PROTECTED_TABLES = {
    "tbltw4Jy0LHWWz5DL": "Canon ID Registry",
    "tblEZ6ctzSoTBsfCW": "Session Ledger",
    "tblsVXX2XnhVLWMVE": "Active Task Queue",
    "tblX88U1VOwmK2fF5": "T0 Decision Log",
}

# Scopes that require a Tier 2 (governance-class) marker, not just Tier 1.
TIER_2_SCOPES = {"tblX88U1VOwmK2fF5"}  # T0 Decision Log

SUPABASE_REFS = {"mksmwqmphdkwwiyfesad", "oufyfdhjjvhrseythgrr"}

MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
FUTURE_SKEW = timedelta(seconds=60)
DEFAULT_MARKER_PATH = ".claude/t0-go.json"

WRITE_KEYWORDS = re.compile(r"\b(DELETE|DROP|TRUNCATE|UPDATE|INSERT)\b", re.IGNORECASE)

# Mutating HTTP / client shapes. Only consulted together with a named
# protected surface, so a stray "-d" elsewhere does not matter.
HTTP_MUTATION = re.compile(
    r"(?:^|\s)(?:-X|--request)[\s=]*(?:POST|PUT|PATCH|DELETE)\b"
    r"|(?:^|\s)--method[\s=]*(?:POST|PUT|PATCH|DELETE)\b"
    r"|(?:^|\s)(?:-d|--data|--data-raw|--data-binary|--data-urlencode|--json|-F|--form|-T|--upload-file|--post-data|--post-file)(?:\s|=|$)"
    r"|\.(?:post|put|patch|delete)\(",
    re.IGNORECASE,
)

DESTRUCTIVE_BASH_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),
    re.compile(r"\bsudo\s+rm\b"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r">\s*/etc/"),
    re.compile(r">\s*/usr/"),
    re.compile(r"\bDROP\s+(TABLE|SCHEMA|DATABASE)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
]

# Authorization material: the marker file, its location override, its issuer.
MARKER_FILENAME_RE = re.compile(r"t0-go\.json", re.IGNORECASE)
MARKER_ENV_RE = re.compile(r"T0_GO_MARKER_PATH")
ISSUER_EXEC_RE = re.compile(
    r"\b(?:python3?|py|sh|bash)\b[^|;&\n]*\bissue_t0_go\b"
    r"|(?:^|[;&|(]\s*)(?:\./|/|~/)?[\w./~-]*issue_t0_go\.py",
    re.IGNORECASE,
)

FILE_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
FILE_PATH_FIELDS = ("file_path", "notebook_path")

MCP_NAME_RE = re.compile(r"^mcp__(?P<server>.+?)__(?P<tool>.+)$")


# --------------------------------------------------------------------------
# Deny plumbing
# --------------------------------------------------------------------------


class Deny(Exception):
    """A deliberate denial. `code` is stable and test-visible."""

    def __init__(self, code: str, message: str, hint: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint

    def render(self) -> str:
        text = f"pre_tool_guard: DENY [{self.code}] {self.message}"
        if self.hint:
            text += f" — {self.hint}"
        return text


def marker_path() -> Path:
    # Same contract as mcp/lib/airtable-client.js: env override, else a path
    # relative to the working directory.
    return Path(os.environ.get("T0_GO_MARKER_PATH") or DEFAULT_MARKER_PATH)


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------


def parse_payload(raw: bytes) -> tuple[str, dict[str, Any]]:
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise Deny("PAYLOAD_TOO_LARGE", f"hook payload exceeds {MAX_PAYLOAD_BYTES} bytes",
                   "the request cannot be classified; refusing")
    if not raw.strip():
        raise Deny("EMPTY_INPUT", "hook received an empty payload",
                   "check that Claude Code is piping the PreToolUse JSON on stdin")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Deny("INVALID_ENCODING", "hook payload is not valid UTF-8", "expected UTF-8 JSON") from None
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError):
        raise Deny("MALFORMED_JSON", "hook payload is not valid JSON",
                   "expected one JSON object with tool_name and tool_input") from None
    if not isinstance(payload, dict):
        raise Deny("INVALID_STRUCTURE", f"hook payload must be a JSON object, got {type(payload).__name__}")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise Deny("INVALID_STRUCTURE", "tool_name is missing or not a non-empty string")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        raise Deny("INVALID_STRUCTURE", "tool_input is missing or not an object", f"tool_name={tool_name!r}")
    return tool_name, tool_input


# --------------------------------------------------------------------------
# T0-GO marker (read-only check)
# --------------------------------------------------------------------------


def load_marker(scope: str = "?", min_tier: int = 1) -> dict[str, Any]:
    path = marker_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise Deny("NO_MARKER", f"no T0-GO marker at {path} for scope '{scope}' (requires Tier {min_tier})",
                   "a human must run hooks/issue_t0_go.py; agents must not") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise Deny("MARKER_UNREADABLE", f"T0-GO marker at {path} is unreadable ({type(exc).__name__})",
                   "treating as absent") from None
    try:
        marker = json.loads(raw)
    except (ValueError, RecursionError):
        raise Deny("MARKER_MALFORMED", f"T0-GO marker at {path} is not valid JSON", "treating as absent") from None
    if not isinstance(marker, dict):
        raise Deny("MARKER_MALFORMED", "T0-GO marker must be a JSON object")

    decision_id = marker.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id:
        raise Deny("MARKER_MALFORMED", "marker decision_id must be a non-empty string")
    scope = marker.get("scope")
    if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
        raise Deny("MARKER_MALFORMED", "marker scope must be a list of strings")
    tier = marker.get("tier", 1)
    if isinstance(tier, bool) or not isinstance(tier, int) or tier not in (1, 2):
        raise Deny("MARKER_MALFORMED", "marker tier must be the integer 1 or 2")
    ttl = marker.get("ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise Deny("MARKER_MALFORMED", "marker ttl_seconds must be a positive integer")
    consumed = marker.get("consumed", False)
    if not isinstance(consumed, bool):
        raise Deny("MARKER_MALFORMED", "marker consumed must be a boolean")
    issued = marker.get("issued_at")
    if not isinstance(issued, str):
        raise Deny("MARKER_MALFORMED", "marker issued_at must be an ISO-8601 string")
    try:
        issued_at = datetime.fromisoformat(issued.replace("Z", "+00:00"))
    except ValueError:
        raise Deny("MARKER_MALFORMED", "marker issued_at is not a valid ISO-8601 timestamp") from None
    if issued_at.tzinfo is None:
        raise Deny("MARKER_MALFORMED", "marker issued_at must carry a timezone (use Z)")

    return {
        "decision_id": decision_id,
        "scope": scope,
        "tier": tier,
        "ttl_seconds": ttl,
        "consumed": consumed,
        "issued_at": issued_at,
    }


def check_t0_go(scope: str, min_tier: int = 1, now: Optional[datetime] = None) -> dict[str, Any]:
    """Read-only check. Does NOT consume the marker (the MCP servers do)."""
    marker = load_marker(scope, min_tier)
    did = marker["decision_id"]
    if marker["consumed"]:
        raise Deny("MARKER_CONSUMED", f"T0-GO marker for decision {did} was already consumed",
                   "a human must issue a fresh one")
    if scope not in marker["scope"]:
        raise Deny("MARKER_SCOPE", f"T0-GO marker for decision {did} does not cover '{scope}'",
                   f"covers: {marker['scope']}")
    if marker["tier"] < min_tier:
        raise Deny("MARKER_TIER", f"T0-GO marker for decision {did} is Tier {marker['tier']}, "
                   f"but '{scope}' requires Tier {min_tier}", "tier is never inferred upward")
    current = now or datetime.now(timezone.utc)
    age = (current - marker["issued_at"]).total_seconds()
    if age < -FUTURE_SKEW.total_seconds():
        raise Deny("MARKER_FUTURE_DATED", f"T0-GO marker for decision {did} is dated in the future")
    if age > marker["ttl_seconds"]:
        raise Deny("MARKER_EXPIRED", f"T0-GO marker for decision {did} expired", "a human must issue a fresh one")
    return marker


# --------------------------------------------------------------------------
# Bash
# --------------------------------------------------------------------------


def _touches_authorization_material(command: str) -> Optional[str]:
    if MARKER_FILENAME_RE.search(command):
        return "mentions the T0-GO marker file"
    if MARKER_ENV_RE.search(command):
        return "sets or references T0_GO_MARKER_PATH"
    custom = os.environ.get("T0_GO_MARKER_PATH")
    if custom and custom in command:
        return "mentions the configured T0-GO marker path"
    if ISSUER_EXEC_RE.search(command):
        return "executes the T0-GO issuer (human-run only)"
    return None


def bash_write_scopes(command: str) -> set[str]:
    if not (WRITE_KEYWORDS.search(command) or HTTP_MUTATION.search(command)):
        return set()
    scopes: set[str] = set()
    for table_id in PROTECTED_TABLES:
        if table_id in command:
            scopes.add(table_id)
    for ref in SUPABASE_REFS:
        if ref in command:
            scopes.add(f"supabase:{ref}")
    if CANON_BASE_ID in command and not any(s in PROTECTED_TABLES for s in scopes):
        scopes.add(CANON_BASE_ID)
    return scopes


def check_bash(command: Any) -> None:
    if not isinstance(command, str):
        raise Deny("INVALID_TOOL_INPUT", "Bash tool_input.command is missing or not a string")
    for pattern in DESTRUCTIVE_BASH_PATTERNS:
        if pattern.search(command):
            raise Deny("DESTRUCTIVE_BASH", f"destructive pattern ({pattern.pattern})", f"command: {command!r}")
    why = _touches_authorization_material(command)
    if why:
        raise Deny("AUTH_MATERIAL", f"command {why}",
                   "agents must not create, edit, move or run authorization material; best-effort check")
    for scope in sorted(bash_write_scopes(command)):
        check_t0_go(scope, min_tier=2 if scope in TIER_2_SCOPES else 1)


# --------------------------------------------------------------------------
# File-write tools
# --------------------------------------------------------------------------


def check_file_write(tool_name: str, tool_input: dict[str, Any]) -> None:
    targets = [tool_input[f] for f in FILE_PATH_FIELDS if f in tool_input]
    if not targets:
        raise Deny("INVALID_TOOL_INPUT", f"{tool_name} has no file_path/notebook_path")
    marker = marker_path()
    try:
        marker_resolved: Optional[Path] = marker.expanduser().resolve()
    except (OSError, RuntimeError):
        marker_resolved = None
    for target in targets:
        if not isinstance(target, str) or not target:
            raise Deny("INVALID_TOOL_INPUT", f"{tool_name} path must be a non-empty string")
        p = Path(target).expanduser()
        try:
            resolved: Optional[Path] = p.resolve()
        except (OSError, RuntimeError):
            resolved = None
        if p.name.lower() == "t0-go.json" or (resolved and marker_resolved and resolved == marker_resolved):
            raise Deny("AUTH_MATERIAL", f"{tool_name} targets the T0-GO marker",
                       "agents must not write authorization material")


# --------------------------------------------------------------------------
# MCP classification
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Classification:
    kind: str  # "read_only" | "protected" | "out_of_scope"
    scope: str = ""
    min_tier: int = 1


ScopeFn = Callable[[dict[str, Any]], Classification]


@dataclass(frozen=True)
class ProtectedRule:
    server: "re.Pattern[str]"
    tool: "re.Pattern[str]"
    resolve: ScopeFn


@dataclass(frozen=True)
class ReadOnlyRule:
    server: "re.Pattern[str]"
    tools: frozenset[str]


def _fixed(scope: str, min_tier: int = 1) -> ScopeFn:
    return lambda _inp: Classification("protected", scope, min_tier)


def _airtable_generic(tool_input: dict[str, Any]) -> Classification:
    base_id = tool_input.get("baseId")
    if not isinstance(base_id, str) or not base_id:
        raise Deny("INVALID_TOOL_INPUT", "Airtable write has no string baseId, so its target cannot be identified",
                   "if this server uses a different parameter name, classify it explicitly")
    table_id = tool_input.get("tableId")
    if table_id is not None and not isinstance(table_id, str):
        raise Deny("INVALID_TOOL_INPUT", "Airtable write tableId must be a string")
    if base_id == CANON_BASE_ID:
        return Classification("protected", table_id or CANON_BASE_ID, 2 if table_id in TIER_2_SCOPES else 1)
    # Writes to a non-Canon base are outside what this guardrail protects.
    return Classification("out_of_scope")


def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern)


# Read-only operations: EXACT tool names only. A name not listed here is not
# read-only, however read-like it looks.
READ_ONLY_RULES: list[ReadOnlyRule] = [
    ReadOnlyRule(_rx(r"github"), frozenset({
        "get_me", "get_commit", "get_file_contents", "get_check_run", "get_job_logs", "get_label",
        "get_latest_release", "get_release_by_tag", "get_tag", "get_team_members", "get_teams",
        "issue_read", "pull_request_read", "actions_get", "actions_list",
        "list_branches", "list_commits", "list_issue_fields", "list_issue_types", "list_issues",
        "list_pull_requests", "list_releases", "list_repository_collaborators", "list_tags",
    })),
    ReadOnlyRule(_rx(r"(?i).*supabase.*"), frozenset({
        "list_tables", "list_migrations", "list_extensions", "list_edge_functions", "list_branches",
        "get_edge_function", "get_logs", "get_advisors", "get_project_url",
        "generate_typescript_types", "search_docs",
    })),
    # Names below are taken from this repo's README / convention and are
    # UNVERIFIED against a live Airtable MCP server (it was unreachable when
    # this table was written). Correct them against the real tool list.
    ReadOnlyRule(_rx(r"Airtable"), frozenset({
        "list_bases", "list_tables_for_base", "list_records_for_table",
    })),
    ReadOnlyRule(_rx(r"sfx-canon-mcp"), frozenset({
        "canon_get_clusters", "canon_get_latest_entry", "canon_get_next_id",
        "canon_get_session_ledger", "canon_query_entry",
    })),
    ReadOnlyRule(_rx(r"sfx-session-mcp"), frozenset({"session_get"})),
    ReadOnlyRule(_rx(r"sfx-atq-mcp"), frozenset({"atq_get_item", "atq_list_open"})),
    ReadOnlyRule(_rx(r"sfx-decisionlog-mcp"), frozenset({"decisionlog_get_latest", "decisionlog_search"})),
    ReadOnlyRule(_rx(r"claude-code-remote"), frozenset({
        "get_session", "list_sessions", "list_events", "get_event", "get_trigger", "list_triggers",
        "list_environments", "get_environment", "list_repos", "list_computer_folders",
        "read_documentation",
    })),
]

# Protected operations: require a valid, scoped T0-GO marker. Checked BEFORE
# the read-only table, so a name in both is protected.
PROTECTED_RULES: list[ProtectedRule] = [
    ProtectedRule(_rx(r"Airtable"), _rx(r"(?:create|update|delete)_.*"), _airtable_generic),
    ProtectedRule(_rx(r"github"),
                  _rx(r"push_files|create_or_update_file|delete_file|merge_pull_request"),
                  _fixed("github:write")),
    ProtectedRule(_rx(r"github"), _rx(r"create_pull_request"), _fixed("github:create_pull_request")),
    ProtectedRule(_rx(r"(?i).*supabase.*"), _rx(r"apply_migration"), _fixed("supabase:apply_migration")),
    ProtectedRule(_rx(r"sfx-session-mcp"), _rx(r"session_open|session_close"), _fixed("tblEZ6ctzSoTBsfCW")),
    ProtectedRule(_rx(r"sfx-atq-mcp"), _rx(r"atq_create_task|atq_update_task"), _fixed("tblsVXX2XnhVLWMVE")),
    ProtectedRule(_rx(r"sfx-decisionlog-mcp"), _rx(r"decisionlog_create_entry"), _fixed("tblX88U1VOwmK2fF5", 2)),
    ProtectedRule(_rx(r"claude-code-remote"), _rx(r"create_trigger"), _fixed("claude-code-remote:create_trigger")),
    ProtectedRule(_rx(r"claude-code-remote"), _rx(r"send_later"), _fixed("claude-code-remote:send_later")),
]


def classify_mcp(tool_name: str, tool_input: dict[str, Any]) -> Classification:
    m = MCP_NAME_RE.match(tool_name)
    if not m:
        raise Deny("UNCLASSIFIED_MCP", f"{tool_name!r} is not a recognizable mcp__<server>__<tool> name",
                   "denied pending classification")
    server, tool = m.group("server"), m.group("tool")
    for p in PROTECTED_RULES:
        if p.server.fullmatch(server) and p.tool.fullmatch(tool):
            return p.resolve(tool_input)
    for r in READ_ONLY_RULES:
        if r.server.fullmatch(server) and tool in r.tools:
            return Classification("read_only")
    raise Deny("UNCLASSIFIED_MCP", f"{tool_name} is not classified read-only or protected",
               "denied pending classification: add it to READ_ONLY_RULES or PROTECTED_RULES in "
               "hooks/pre_tool_guard.py (reviewed change)")


# --------------------------------------------------------------------------
# Decision + entrypoint
# --------------------------------------------------------------------------


def decide(tool_name: str, tool_input: dict[str, Any]) -> None:
    if tool_name == "Bash":
        check_bash(tool_input.get("command"))
        return
    if tool_name in FILE_WRITE_TOOLS:
        check_file_write(tool_name, tool_input)
        return
    if tool_name.startswith("mcp__"):
        c = classify_mcp(tool_name, tool_input)
        if c.kind == "protected":
            check_t0_go(c.scope, min_tier=c.min_tier)
        return
    # Other built-in (non-MCP) tools are outside this policy.


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
        tool_name, tool_input = parse_payload(raw)
        decide(tool_name, tool_input)
        return 0
    except Deny as d:
        _emit(d.render())
        return 2
    except Exception as exc:  # noqa: BLE001 — fail closed on ANY internal error
        _emit(f"pre_tool_guard: DENY [INTERNAL_ERROR] {type(exc).__name__}: {exc} — failing closed")
        return 2


def _emit(message: str) -> None:
    try:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001 — never let a stderr failure change the exit code
        pass


if __name__ == "__main__":
    sys.exit(main())
