"""Security acceptance tests: hooks/pre_tool_guard.py run as Claude Code runs it: PreToolUse JSON on
stdin, decision in the exit code. 2 blocks; Claude Code treats every other
exit code (including a crash's exit 1) as non-blocking, so the call goes
through. Tests therefore assert the exact exit code.

Behaviour that is known to be unsafe but deliberately not changed lives in
test_known_gaps.py, not here."""

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

@pytest.mark.parametrize("raw", ["[]", "null", "42", '"Bash"'])
def test_non_object_payload_does_not_crash_the_hook(run_hook, raw):
    # A crash (exit 1) is an unintended fail-open. Which deliberate exit code
    # this input gets is the documented T12 decision, pinned in
    # test_known_gaps.py.
    proc = run_hook(None, raw_stdin=raw)
    assert proc.returncode in (ALLOW, BLOCK)
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


def test_non_string_tool_name_does_not_crash_the_hook(run_hook):
    proc = run_hook({"tool_name": 7, "tool_input": {}})
    assert proc.returncode in (ALLOW, BLOCK) and "Traceback" not in proc.stderr


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


def test_generic_airtable_write_to_another_base_is_denied_as_unclassified(run_hook, marker_path):
    # Owner decision 2 (reconciliation 1c). PR #2 asserted ALLOW here ("not
    # this hook's concern"); non-Canon Airtable writes are now denied, even
    # with a marker naming that base.
    payload = mcp("mcp__Airtable__create_records_for_table", baseId="appZfrNIUEip5MazD", tableId=SESSION)
    assert run_hook(payload).returncode == BLOCK
    write_marker(marker_path, valid_marker(["appZfrNIUEip5MazD", SESSION], tier=2))
    proc = run_hook(payload)
    assert proc.returncode == BLOCK and "UNCLASSIFIED_MCP" in proc.stderr


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


def test_absent_base_id_blocks(run_hook):
    # e.g. create_base takes workspaceId, not baseId. PR #2 asserted ALLOW;
    # under owner decision 2 a write whose base cannot be identified as the
    # Canon base is denied.
    proc = run_hook(mcp("mcp__Airtable__create_base", workspaceId="wspZfrNIUEip5MazD"))
    assert proc.returncode == BLOCK and "Traceback" not in proc.stderr


# --- configuration consistency -------------------------------------------

# Rewritten for the reconciled hook: PR #2 compared the settings matchers
# with MCP_WRITE_PATTERNS (a name list). The reconciled hook has no such
# list; it denies every MCP call it cannot classify, which only works if
# every MCP call reaches it. So the invariant is now "routing is total".

def test_settings_route_every_mcp_bash_and_file_write_call_to_the_hook():
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    matchers = [re.compile(f"^(?:{e['matcher']})$") for e in settings["hooks"]["PreToolUse"]]
    names = [p["tool_name"] for p, _, _ in GATED_TOOLS] + [
        "mcp__github__create_or_update_file", "mcp__github__delete_file", "mcp__Airtable__update_field",
        "mcp__Airtable__list_records_for_table", "mcp__sfx-session-mcp__session_get", "Bash", "Write", "Edit",
        "MultiEdit", "NotebookEdit", "mcp__Airtable__submit_form", "mcp__Supabase__execute_sql",
        "mcp__github__create_branch", "mcp__plugin_airtable_airtable__create_records_for_table",
        "mcp__some-future-server__any_tool",
    ]
    for name in names:
        assert any(m.match(name) for m in matchers), name


def test_mcp_config_server_names_match_hook_rules(guard):
    servers = set(json.loads((REPO / "config" / "mcp.json.example").read_text())["mcpServers"])
    with_protected = {s for s in servers if any(r.server.fullmatch(s) for r in guard.PROTECTED_RULES)}
    with_reads = {s for s in servers if any(r.server.fullmatch(s) for r in guard.READ_ONLY_RULES)}
    assert with_protected == servers - {"sfx-canon-mcp"}  # sfx-canon-mcp has no write tool
    assert with_reads == servers  # every configured server has its read tools classified


# --- known gaps from PR #2 that the reconciled hook closes --------------------
# These were pinned as ALLOW in test_known_gaps.py. The same payloads are now
# acceptance tests asserting BLOCK. Gaps that remain open are still pinned
# there.

@pytest.mark.parametrize(
    "command",
    [
        "echo '{}' > .claude/t0-go.json",
        "python3 hooks/issue_t0_go.py --decision-id X --scope tblEZ6ctzSoTBsfCW",
        "cp /tmp/m.json .claude/t0-go.json",
    ],
)
def test_closed_t10_direct_marker_writes_and_issuer_runs_block(run_hook, command):
    proc = run_hook(bash(command))
    assert proc.returncode == BLOCK and "AUTH_MATERIAL" in proc.stderr


@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit", "NotebookEdit"])
def test_closed_t10_file_tools_are_routed_and_marker_writes_block(run_hook, tool):
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    matchers = [re.compile(f"^(?:{e['matcher']})$") for e in settings["hooks"]["PreToolUse"]]
    assert any(m.match(tool) for m in matchers)
    field = "notebook_path" if tool == "NotebookEdit" else "file_path"
    assert run_hook({"tool_name": tool, "tool_input": {field: ".claude/t0-go.json"}}).returncode == BLOCK


CLOSED_T11 = [
    mcp("mcp__Airtable__submit_form", baseId=CANON_BASE, pageId="pagXXXXXXXXXXXXXX"),
    mcp("mcp__Airtable__revert_action", baseId=CANON_BASE, actionId="actXXXXXXXXXXXXXX"),
    mcp("mcp__plugin_airtable_airtable__create_records_for_table", baseId=CANON_BASE, tableId=SESSION),
    mcp("mcp__Supabase__execute_sql", query="DROP TABLE x"),
    mcp("mcp__github__create_branch"),
    mcp("mcp__github__enable_pr_auto_merge"),
]


@pytest.mark.parametrize("payload", CLOSED_T11, ids=[p["tool_name"] for p in CLOSED_T11])
def test_closed_t11_unclassified_write_capable_tools_block_even_with_a_marker(run_hook, marker_path, payload):
    write_marker(marker_path, valid_marker([SESSION, CANON_BASE, "github:write", "supabase:apply_migration"], tier=2))
    proc = run_hook(payload)
    assert proc.returncode == BLOCK and "UNCLASSIFIED_MCP" in proc.stderr


def test_closed_t11_http_patch_to_a_canon_table_needs_a_marker(run_hook, marker_path):
    cmd = f"curl -X PATCH https://api.airtable.com/v0/{CANON_BASE}/{SESSION}/recXXXXXXXXXXXXXX"
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker([SESSION]))
    assert run_hook(bash(cmd)).returncode == ALLOW


@pytest.mark.parametrize("stdin", ["", "{not json", "[]"])
def test_closed_t12_unparseable_or_non_object_input_blocks(run_hook, stdin):
    # Owner decision 1: malformed input denies with exit 2.
    proc = run_hook(None, raw_stdin=stdin)
    assert proc.returncode == BLOCK and "Traceback" not in proc.stderr
