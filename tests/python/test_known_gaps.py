"""KNOWN GAPS: these are not security acceptance tests.

Each test pins current behaviour that is unsafe, or not proven safe, but was
deliberately left unchanged because fixing it is an authorization-model
decision for T0 (see docs/THREAT-MODEL.md and docs/adr/). A passing test here
means "the gap is still exactly as documented", never "this is protected".
When a gap is closed, delete its test here and add an acceptance test in
test_pre_tool_guard.py / test_harness_failures.py that asserts the new,
safe behaviour.

Run separately: python -m pytest tests/python -m known_gap
"""

import json
import re

import pytest

from conftest import REPO, valid_marker

pytestmark = pytest.mark.known_gap

CANON_BASE = "appVftexD3KJRcdij"
SESSION = "tblEZ6ctzSoTBsfCW"
ALLOW = 0


def mcp(tool_name, **tool_input):
    return {"tool_name": tool_name, "tool_input": tool_input}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# --- T9: replay on hook-only write paths ------------------------------------

@pytest.mark.parametrize("tool", ["mcp__github__push_files", "mcp__Supabase__apply_migration"])
def test_gap_t9_hook_only_paths_never_consume_the_marker(run_hook, marker_path, tool):
    scope = "github:write" if "github" in tool else "supabase:apply_migration"
    marker_path.write_text(json.dumps(valid_marker([scope])))
    before = marker_path.read_text()
    assert [run_hook(mcp(tool)).returncode for _ in range(3)] == [ALLOW, ALLOW, ALLOW]
    assert marker_path.read_text() == before


# --- T10: the agent session can create its own marker -----------------------
# The hook only sees tools its matchers route to it, and treats these Bash
# commands as harmless. Nothing here is executed: the hook only inspects the
# command string.

@pytest.mark.parametrize(
    "command",
    [
        "echo '{}' > .claude/t0-go.json",
        "python3 hooks/issue_t0_go.py --decision-id X --scope tblEZ6ctzSoTBsfCW",
        "cp /tmp/m.json .claude/t0-go.json",
    ],
)
def test_gap_t10_bash_can_write_the_marker_or_run_the_issuer(run_hook, command):
    assert run_hook(bash(command)).returncode == ALLOW


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "NotebookEdit"])
def test_gap_t10_file_tools_are_never_routed_to_the_hook(tool):
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    matchers = [re.compile(f"^(?:{e['matcher']})$") for e in settings["hooks"]["PreToolUse"]]
    assert not any(m.match(tool) for m in matchers)


# --- T11: write-capable surfaces outside the matchers -------------------------

UNGATED_WRITE_CAPABLE = [
    mcp("mcp__Airtable__submit_form", baseId=CANON_BASE, pageId="pagXXXXXXXXXXXXXX"),
    mcp("mcp__Airtable__revert_action", baseId=CANON_BASE, actionId="actXXXXXXXXXXXXXX"),
    mcp("mcp__plugin_airtable_airtable__create_records_for_table", baseId=CANON_BASE, tableId=SESSION),
    mcp("mcp__Supabase__execute_sql", query="DROP TABLE x"),
    mcp("mcp__github__create_branch"),
    mcp("mcp__github__enable_pr_auto_merge"),
]


@pytest.mark.parametrize("payload", UNGATED_WRITE_CAPABLE, ids=[p["tool_name"] for p in UNGATED_WRITE_CAPABLE])
def test_gap_t11_write_capable_tools_outside_the_matchers(run_hook, payload):
    assert run_hook(payload).returncode == ALLOW


def test_gap_t11_http_verbs_are_not_write_keywords(run_hook):
    cmd = f"curl -X PATCH https://api.airtable.com/v0/{CANON_BASE}/{SESSION}/recXXXXXXXXXXXXXX"
    assert run_hook(bash(cmd)).returncode == ALLOW


# --- T12: undecodable or empty hook input fails open --------------------------

@pytest.mark.parametrize("stdin", ["", "{not json", "[]"])
def test_gap_t12_unparseable_or_non_object_input_is_allowed(run_hook, stdin):
    assert run_hook(None, raw_stdin=stdin).returncode == ALLOW


# --- TTL has no upper bound ---------------------------------------------------

def test_gap_ttl_is_unbounded(guard, marker_path):
    marker_path.write_text(json.dumps(valid_marker([SESSION], ttl_seconds=10 * 365 * 24 * 3600)))
    guard.check_t0_go(SESSION, min_tier=1)  # returns: allowed
