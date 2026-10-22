"""hooks/pre_tool_guard.py run as Claude Code runs it: PreToolUse JSON on
stdin, decision in the exit code. 2 blocks; Claude Code treats every other
exit code (including a crash's exit 1) as non-blocking, so the call goes
through. Tests therefore assert the exact exit code."""

import json
import re
from pathlib import Path

import pytest

from conftest import REPO, valid_marker

CANON_BASE = "appVftexD3KJRcdij"
SESSION, ATQ, DECISION_LOG, REGISTRY = (
    "tblEZ6ctzSoTBsfCW", "tblsVXX2XnhVLWMVE", "tblX88U1VOwmK2fF5", "tbltw4Jy0LHWWz5DL",
)
BLOCK, ALLOW = 2, 0


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def mcp(tool_name, **tool_input):
    return {"tool_name": tool_name, "tool_input": tool_input}


def write_marker(path, marker):
    path.write_text(json.dumps(marker))


# --- malformed hook input ---------------------------------------------------

def test_undecodable_stdin_is_allowed_as_documented(run_hook):
    # Documented fail-open for harness parsing bugs (flagged for T0 review).
    assert run_hook(None, raw_stdin="{not json").returncode == ALLOW


@pytest.mark.parametrize("raw", ["[]", "null", "42", '"Bash"'])
def test_non_object_payload_takes_the_documented_path_without_crashing(run_hook, raw):
    proc = run_hook(None, raw_stdin=raw)
    assert proc.returncode == ALLOW
    assert "Traceback" not in proc.stderr


@pytest.mark.parametrize(
    "payload",
    [
        {"tool_name": "Bash", "tool_input": "rm -rf /"},
        {"tool_name": "Bash", "tool_input": {"command": ["rm", "-rf", "/"]}},
        {"tool_name": "Bash", "tool_input": {"command": None}},
        {"tool_name": "mcp__sfx-session-mcp__session_open", "tool_input": "x"},
        {"tool_name": "mcp__Airtable__create_records_for_table", "tool_input": ["x"]},
    ],
)
def test_malformed_input_on_a_guarded_tool_blocks(run_hook, payload):
    proc = run_hook(payload)
    assert proc.returncode == BLOCK, proc.stderr
    assert "Traceback" not in proc.stderr


def test_non_string_tool_name_is_allowed_without_crashing(run_hook):
    proc = run_hook({"tool_name": 7, "tool_input": {}})
    assert proc.returncode == ALLOW and "Traceback" not in proc.stderr


@pytest.mark.parametrize("raw", ["[1]", "null", '"x"'])
def test_malformed_marker_file_blocks_not_crashes(run_hook, marker_path, raw):
    marker_path.write_text(raw)
    proc = run_hook(mcp("mcp__sfx-session-mcp__session_open"))
    assert proc.returncode == BLOCK and "Traceback" not in proc.stderr


# --- Bash surface -------------------------------------------------------------

@pytest.mark.parametrize("cmd", ["rm -rf build", "sudo rm x", "chmod 777 f", "echo x > /etc/hosts",
                                 "psql -c 'DROP TABLE t'", "psql -c 'truncate table t'"])
def test_destructive_bash_blocks(run_hook, cmd):
    assert run_hook(bash(cmd)).returncode == BLOCK


def test_harmless_bash_allows(run_hook):
    assert run_hook(bash("ls -la && git status")).returncode == ALLOW


def test_sql_write_naming_a_protected_table_needs_a_marker(run_hook, marker_path):
    cmd = f"curl ... -d 'DELETE FROM {SESSION}'"
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker([SESSION]))
    assert run_hook(bash(cmd)).returncode == ALLOW


def test_sql_write_naming_the_decision_log_needs_tier_2(run_hook, marker_path):
    cmd = f"curl ... -d 'UPDATE {DECISION_LOG}'"
    write_marker(marker_path, valid_marker([DECISION_LOG], tier=1))
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker([DECISION_LOG], tier=2))
    assert run_hook(bash(cmd)).returncode == ALLOW


def test_sql_write_naming_only_the_canon_base_is_gated_on_the_base(run_hook, marker_path):
    cmd = f"curl .../{CANON_BASE}/tblOther -d 'INSERT x'"
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker([CANON_BASE]))
    assert run_hook(bash(cmd)).returncode == ALLOW


def test_supabase_ref_with_write_keyword_is_gated(run_hook):
    assert run_hook(bash("psql mksmwqmphdkwwiyfesad -c 'DELETE FROM x'")).returncode == BLOCK


def test_documents_gap_http_verbs_are_not_write_keywords(run_hook):
    # T11, flagged not fixed: a raw REST write to a protected table without
    # any SQL keyword is not gated by the Bash guard.
    cmd = f"curl -X PATCH https://api.airtable.com/v0/{CANON_BASE}/{SESSION}/recXXXXXXXXXXXXXX"
    assert run_hook(bash(cmd)).returncode == ALLOW


# --- MCP tool-name matching ------------------------------------------------

GATED_TOOLS = [
    (mcp("mcp__sfx-session-mcp__session_open"), [SESSION], 1),
    (mcp("mcp__sfx-session-mcp__session_close"), [SESSION], 1),
    (mcp("mcp__sfx-atq-mcp__atq_create_task"), [ATQ], 1),
    (mcp("mcp__sfx-atq-mcp__atq_update_task"), [ATQ], 1),
    (mcp("mcp__sfx-decisionlog-mcp__decisionlog_create_entry"), [DECISION_LOG], 2),
    (mcp("mcp__github__push_files"), ["github:write"], 1),
    (mcp("mcp__github__merge_pull_request"), ["github:write"], 1),
    (mcp("mcp__Supabase__apply_migration"), ["supabase:apply_migration"], 1),
    (mcp("mcp__Airtable__create_records_for_table", baseId=CANON_BASE, tableId=SESSION), [SESSION], 1),
    (mcp("mcp__Airtable__delete_records_for_table", baseId=CANON_BASE, tableId=REGISTRY), [REGISTRY], 1),
    (mcp("mcp__Airtable__create_table", baseId=CANON_BASE), [CANON_BASE], 1),
]


@pytest.mark.parametrize("payload, scope, tier", GATED_TOOLS, ids=[p["tool_name"] for p, _, _ in GATED_TOOLS])
def test_gated_tool_blocks_without_marker_and_allows_with_one(run_hook, marker_path, payload, scope, tier):
    assert run_hook(payload).returncode == BLOCK
    write_marker(marker_path, valid_marker(["tblWRONGWRONGWRO1"], tier=tier))
    assert run_hook(payload).returncode == BLOCK
    write_marker(marker_path, valid_marker(scope, tier=tier))
    assert run_hook(payload).returncode == ALLOW


@pytest.mark.parametrize("read_tool", ["mcp__sfx-session-mcp__session_get", "mcp__sfx-atq-mcp__atq_list_open",
                                       "mcp__sfx-canon-mcp__canon_get_latest_entry",
                                       "mcp__Airtable__list_records_for_table"])
def test_read_tools_are_never_gated(run_hook, read_tool):
    assert run_hook(mcp(read_tool, baseId=CANON_BASE, tableId=SESSION)).returncode == ALLOW


def test_generic_airtable_write_to_decision_log_needs_tier_2(run_hook, marker_path):
    # Before this fix the minimum tier came from the tool kind, so a Tier 1
    # marker scoped to the Decision Log let the generic Airtable MCP write it.
    payload = mcp("mcp__Airtable__create_records_for_table", baseId=CANON_BASE, tableId=DECISION_LOG)
    write_marker(marker_path, valid_marker([DECISION_LOG], tier=1))
    assert run_hook(payload).returncode == BLOCK
    write_marker(marker_path, valid_marker([DECISION_LOG], tier=2))
    assert run_hook(payload).returncode == ALLOW


def test_generic_airtable_write_to_another_base_is_not_this_hooks_concern(run_hook):
    payload = mcp("mcp__Airtable__create_records_for_table", baseId="appZfrNIUEip5MazD", tableId=SESSION)
    assert run_hook(payload).returncode == ALLOW


# --- missing or malformed target identifiers ---------------------------------

@pytest.mark.parametrize(
    "tool_input",
    [
        {"baseId": CANON_BASE, "tableId": 123},
        {"baseId": CANON_BASE, "tableId": [SESSION]},
        {"baseId": [CANON_BASE], "tableId": SESSION},
        {"baseId": {"id": CANON_BASE}, "tableId": SESSION},
        {"baseId": None, "tableId": SESSION},
    ],
)
def test_malformed_airtable_target_blocks(run_hook, marker_path, tool_input):
    write_marker(marker_path, valid_marker([SESSION, CANON_BASE]))
    proc = run_hook({"tool_name": "mcp__Airtable__update_records_for_table", "tool_input": tool_input})
    assert proc.returncode == BLOCK and "Traceback" not in proc.stderr


def test_canon_base_without_table_is_gated_on_the_base(run_hook, marker_path):
    payload = mcp("mcp__Airtable__update_records_for_table", baseId=CANON_BASE)
    write_marker(marker_path, valid_marker([SESSION]))
    assert run_hook(payload).returncode == BLOCK
    write_marker(marker_path, valid_marker([CANON_BASE]))
    assert run_hook(payload).returncode == ALLOW


def test_absent_base_id_is_not_gated(run_hook):
    # e.g. create_base takes workspaceId, not baseId. Unchanged behaviour.
    assert run_hook(mcp("mcp__Airtable__create_base", workspaceId="wspZfrNIUEip5MazD")).returncode == ALLOW


# --- replay on hook-only write paths (T9, flagged not fixed) -----------------

@pytest.mark.parametrize("tool", ["mcp__github__push_files", "mcp__Supabase__apply_migration"])
def test_documents_gap_hook_only_paths_never_consume_the_marker(run_hook, marker_path, tool):
    scope = "github:write" if "github" in tool else "supabase:apply_migration"
    write_marker(marker_path, valid_marker([scope]))
    before = marker_path.read_text()
    assert [run_hook(mcp(tool)).returncode for _ in range(3)] == [ALLOW, ALLOW, ALLOW]
    assert marker_path.read_text() == before


# --- matcher coverage against real tool names (T11, flagged not fixed) -------

UNGATED_WRITE_CAPABLE = [
    mcp("mcp__Airtable__submit_form", baseId=CANON_BASE, pageId="pagXXXXXXXXXXXXXX"),
    mcp("mcp__Airtable__revert_action", baseId=CANON_BASE, actionId="actXXXXXXXXXXXXXX"),
    mcp("mcp__plugin_airtable_airtable__create_records_for_table", baseId=CANON_BASE, tableId=SESSION),
    mcp("mcp__Supabase__execute_sql", query="DROP TABLE x"),
    mcp("mcp__github__create_branch"),
    mcp("mcp__github__enable_pr_auto_merge"),
]


@pytest.mark.parametrize("payload", UNGATED_WRITE_CAPABLE, ids=[p["tool_name"] for p in UNGATED_WRITE_CAPABLE])
def test_documents_gap_write_capable_tools_outside_the_matchers(run_hook, payload):
    assert run_hook(payload).returncode == ALLOW


def test_settings_matchers_route_exactly_the_hooks_write_patterns(guard):
    """config/settings.json.example decides which tool calls reach the hook
    at all; MCP_WRITE_PATTERNS decides which of those it gates. They must
    agree, or a pattern is dead code (hook never invoked) or a matcher sends
    calls the hook silently allows."""
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    matchers = [re.compile(f"^(?:{e['matcher']})$") for e in settings["hooks"]["PreToolUse"]]
    names = [p["tool_name"] for p, _, _ in GATED_TOOLS] + [p["tool_name"] for p in UNGATED_WRITE_CAPABLE] + [
        "mcp__github__create_or_update_file", "mcp__github__delete_file", "mcp__Airtable__update_field",
        "mcp__Airtable__list_records_for_table", "mcp__sfx-session-mcp__session_get", "Bash", "Write", "Edit",
    ]
    for name in names:
        routed = any(m.match(name) for m in matchers)
        gated = name == "Bash" or any(p.match(name) for p, _ in guard.MCP_WRITE_PATTERNS)
        assert routed == gated, name


def test_mcp_config_server_names_match_hook_tool_prefixes(guard):
    servers = json.loads((REPO / "config" / "mcp.json.example").read_text())["mcpServers"]
    prefixes = {p.pattern.split("__")[1] for p, kind in guard.MCP_WRITE_PATTERNS if kind.startswith("sfx_")}
    assert prefixes == {s for s in servers if s != "sfx-canon-mcp"}
