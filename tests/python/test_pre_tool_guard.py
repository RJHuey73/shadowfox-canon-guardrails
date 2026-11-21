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

@pytest.mark.parametrize("raw", ["", "{not json", "[]", "null", "42", '"Bash"'])
def test_undecodable_or_non_object_input_blocks(run_hook, raw):
    # T12: the hook only sees calls its matchers route to it, so input it
    # cannot read is never a reason to let the call through.
    proc = run_hook(None, raw_stdin=raw)
    assert proc.returncode == BLOCK, proc.stderr
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


@pytest.mark.parametrize("payload", [{"tool_name": 7, "tool_input": {}}, {"tool_name": ""}, {"tool_input": {}}])
def test_missing_or_non_string_tool_name_blocks(run_hook, payload):
    proc = run_hook(payload)
    assert proc.returncode == BLOCK and "Traceback" not in proc.stderr


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


@pytest.mark.parametrize(
    "cmd",
    [
        f"curl -X PATCH https://api.airtable.com/v0/{CANON_BASE}/{SESSION}/recXXXXXXXXXXXXXX",
        f"curl --request=POST https://api.airtable.com/v0/{CANON_BASE}/{SESSION}",
        f"curl https://api.airtable.com/v0/{CANON_BASE}/{SESSION} -H 'x: y' -d '{{}}'",
        f"curl --json '{{}}' https://api.airtable.com/v0/{CANON_BASE}/{SESSION}",
        f"python3 -c \"import requests; requests.post('https://api.airtable.com/v0/{CANON_BASE}/{SESSION}')\"",
        f"node -e \"fetch('https://api.airtable.com/v0/{CANON_BASE}/{SESSION}', {{method: 'DELETE'}})\"",
    ],
)
def test_http_write_naming_a_protected_table_needs_a_marker(run_hook, marker_path, cmd):
    # T11: HTTP verbs gate like SQL write keywords.
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker([SESSION]))
    assert run_hook(bash(cmd)).returncode == ALLOW


def test_http_read_of_a_protected_table_is_not_gated(run_hook):
    cmd = f"curl -s https://api.airtable.com/v0/{CANON_BASE}/{SESSION}?maxRecords=1"
    assert run_hook(bash(cmd)).returncode == ALLOW


def test_http_write_to_notion_needs_a_notion_marker(run_hook, marker_path):
    cmd = "curl -X PATCH https://api.notion.com/v1/pages/abc -d '{}'"
    assert run_hook(bash(cmd)).returncode == BLOCK
    write_marker(marker_path, valid_marker(["notion:write"]))
    assert run_hook(bash(cmd)).returncode == ALLOW


@pytest.mark.parametrize(
    "cmd",
    [
        "echo '{}' > .claude/t0-go.json",
        "cp /tmp/m.json .claude/t0-go.json",
        "cat .claude/t0-go.json",
        "rm .claude/t0-go.json.lock",
        "python3 hooks/issue_t0_go.py --decision-id X --scope tblEZ6ctzSoTBsfCW",
        "python3 /abs/path/hooks/issue_t0_go.py -h",
    ],
)
def test_bash_touching_the_marker_or_the_issuer_blocks(run_hook, marker_path, cmd):
    # T10 (partial). Blocks even with a valid marker present: a marker never
    # authorizes minting another one.
    write_marker(marker_path, valid_marker([SESSION, CANON_BASE]))
    assert run_hook(bash(cmd)).returncode == BLOCK


def test_bash_marker_match_ignores_case(run_hook):
    assert run_hook(bash("echo '{}' > .claude/T0-GO.JSON")).returncode == BLOCK


def test_file_tools_cannot_write_the_configured_marker_lock(run_hook, marker_path):
    lock = f"{marker_path}.lock"
    assert run_hook({"tool_name": "Write", "tool_input": {"file_path": lock}}).returncode == BLOCK


def test_bash_naming_a_custom_marker_path_blocks(run_hook, marker_path):
    # run_hook points T0_GO_MARKER_PATH at a tmp file: its full path counts too.
    assert run_hook(bash(f"cp /tmp/x {marker_path}")).returncode == BLOCK


# --- file tools (T10, partial) ---------------------------------------------

@pytest.mark.parametrize(
    "tool, field, path",
    [
        ("Write", "file_path", ".claude/t0-go.json"),
        ("Write", "file_path", "/somewhere/else/t0-go.json"),
        ("Edit", "file_path", ".claude/t0-go.json"),
        ("MultiEdit", "file_path", ".claude/t0-go.json"),
        ("Write", "file_path", ".claude/t0-go.json.lock"),
        ("NotebookEdit", "notebook_path", ".claude/t0-go.json"),
        ("Write", "file_path", ".claude/T0-GO.json"),
    ],
)
def test_file_tools_cannot_write_the_marker(run_hook, tool, field, path):
    assert run_hook({"tool_name": tool, "tool_input": {field: path, "content": "{}"}}).returncode == BLOCK


def test_file_tools_cannot_write_the_configured_marker_path(run_hook, marker_path):
    assert run_hook({"tool_name": "Write", "tool_input": {"file_path": str(marker_path)}}).returncode == BLOCK


def test_file_tools_cannot_write_through_a_symlink_to_the_marker(run_hook, marker_path, tmp_path):
    marker_path.write_text("{}")
    link = tmp_path / "innocent.json"
    link.symlink_to(marker_path)
    assert run_hook({"tool_name": "Write", "tool_input": {"file_path": str(link)}}).returncode == BLOCK


def test_file_tools_writing_other_files_are_allowed(run_hook):
    payload = {"tool_name": "Edit", "tool_input": {"file_path": "src/app.py", "old_string": "a", "new_string": "b"}}
    assert run_hook(payload).returncode == ALLOW


@pytest.mark.parametrize("tool_input", [{}, {"file_path": ""}, {"file_path": 7}, "x"])
def test_file_tool_with_no_usable_path_blocks(run_hook, tool_input):
    assert run_hook({"tool_name": "Write", "tool_input": tool_input}).returncode == BLOCK


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
    # T11: write-capable tools that used to fall outside the matchers.
    (mcp("mcp__Airtable__submit_form", baseId=CANON_BASE, pageId="pagXXXXXXXXXXXXXX"), [CANON_BASE], 1),
    (mcp("mcp__Airtable__revert_action", baseId=CANON_BASE, actionId="actXXXXXXXXXXXXXX"), [CANON_BASE], 1),
    (mcp("mcp__plugin_airtable_airtable__create_records_for_table", baseId=CANON_BASE, tableId=SESSION), [SESSION], 1),
    (mcp("mcp__Supabase__execute_sql", query="DROP TABLE x"), ["supabase:execute_sql"], 1),
    (mcp("mcp__Supabase__execute_sql", query="select 1"), ["supabase:execute_sql"], 1),
    (mcp("mcp__Supabase__deploy_edge_function"), ["supabase:deploy_edge_function"], 1),
    (mcp("mcp__supabase-telemetry__execute_sql"), ["supabase:execute_sql"], 1),
    (mcp("mcp__github__create_branch"), ["github:write"], 1),
    (mcp("mcp__github__enable_pr_auto_merge"), ["github:write"], 1),
    (mcp("mcp__Notion__notion-update-page"), ["notion:write"], 1),
    (mcp("mcp__Notion__notion-create-pages"), ["notion:write"], 1),
    # Deny by default: a tool a known sfx server adds later, and an unknown sfx server.
    (mcp("mcp__sfx-session-mcp__session_delete"), [SESSION], 1),
    (mcp("mcp__sfx-canon-mcp__canon_create_entry"), [REGISTRY], 1),
    (mcp("mcp__sfx-newthing-mcp__anything"), [CANON_BASE], 1),
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
                                       "mcp__sfx-canon-mcp__canon_get_next_id",
                                       "mcp__sfx-decisionlog-mcp__decisionlog_search",
                                       "mcp__Airtable__list_records_for_table",
                                       "mcp__Airtable__display_records_for_table",
                                       "mcp__Airtable__search_records",
                                       "mcp__plugin_airtable_airtable__list_records_for_table",
                                       "mcp__Supabase__list_tables", "mcp__Supabase__get_advisors",
                                       "mcp__Supabase__query_logs",
                                       "mcp__github__get_file_contents", "mcp__github__list_pull_requests",
                                       "mcp__Notion__notion-fetch", "mcp__Notion__notion-search",
                                       "mcp__Notion__notion-query-data-sources"])
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


# --- configuration consistency -------------------------------------------

ROUTING_NAMES = [p["tool_name"] for p, _, _ in GATED_TOOLS] + [
    "mcp__github__create_or_update_file", "mcp__github__delete_file", "mcp__Airtable__update_field",
    "mcp__Airtable__list_records_for_table", "mcp__sfx-session-mcp__session_get", "mcp__AIRTABLE__x",
    "mcp__plugin_github_github__push_files", "mcp__claude_ai_Notion__notion-create-pages",
    "mcp__Zapier__execute_zapier_write_action", "mcp__Vercel__create_project",
    "Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "Read", "Grep",
]


def settings_matchers():
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    return [re.compile(f"^(?:{e['matcher']})$") for e in settings["hooks"]["PreToolUse"]]


@pytest.mark.parametrize("name", ROUTING_NAMES)
def test_every_tool_the_hook_governs_is_routed_to_it(guard, name):
    """config/settings.json.example decides which calls reach the hook at
    all. A tool the hook would gate but the matchers never route is a silent
    hole; routing a tool the hook then allows is harmless."""
    governed = name == "Bash" or name in guard.FILE_WRITE_TOOLS or guard.governed_namespace(name) is not None
    routed = any(m.match(name) for m in settings_matchers())
    if governed:
        assert routed, name


def test_settings_matcher_keywords_match_the_hook(guard):
    keywords = {k for ks in guard.GOVERNED_SERVER_KEYWORDS.values() for k in ks}
    settings = json.loads((REPO / "config" / "settings.json.example").read_text())
    mcp_matchers = [e["matcher"] for e in settings["hooks"]["PreToolUse"] if e["matcher"].startswith("mcp__")]
    assert len(mcp_matchers) == 1
    routed = set(re.search(r"\((.*)\)", mcp_matchers[0]).group(1).split("|"))
    assert routed == keywords


def test_routed_but_ungoverned_tool_is_allowed(run_hook):
    # The mcp matcher can match a keyword in the tool part; the hook keys on
    # the server part, so this reaches the hook and is allowed.
    assert run_hook(mcp("mcp__Zapier__airtable_lookup")).returncode == ALLOW


def test_mcp_config_server_names_match_hook_sfx_servers(guard):
    servers = json.loads((REPO / "config" / "mcp.json.example").read_text())["mcpServers"]
    assert set(servers) == set(guard.SFX_SERVERS)


SFX_WRITE_TOOLS = {"session_open", "session_close", "atq_create_task", "atq_update_task", "decisionlog_create_entry"}


@pytest.mark.parametrize("server", ["sfx-canon-mcp", "sfx-session-mcp", "sfx-atq-mcp", "sfx-decisionlog-mcp"])
def test_sfx_read_lists_match_the_servers_tools(guard, server):
    """Every tool a server registers is either on the hook's read list or a
    known write. A new tool fails this until someone decides which it is."""
    source = (REPO / "mcp" / f"{server}.js").read_text()
    tools = set(re.findall(r'"((?:session|atq|canon|decisionlog)_[a-z_]+)"', source))
    reads = guard.SFX_SERVERS[server][2]
    assert reads <= tools
    assert tools - reads <= SFX_WRITE_TOOLS, tools - reads


# --- marker lifetime cap ------------------------------------------------------

ISSUER = REPO / "hooks" / "issue_t0_go.py"


def _issuer_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("issue_t0_go_under_test", ISSUER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ttl_cap_is_the_same_in_the_issuer_and_both_readers(guard):
    js = (REPO / "mcp" / "lib" / "airtable-client.js").read_text()
    js_cap = int(re.search(r"MAX_TTL_SECONDS = ([0-9_]+);", js).group(1).replace("_", ""))
    assert guard.MAX_TTL_SECONDS == _issuer_module().MAX_TTL_SECONDS == js_cap


@pytest.mark.parametrize("ttl, ok", [("3600", True), ("1", True), ("3601", False), ("0", False), ("-5", False)])
def test_issuer_refuses_a_ttl_outside_the_cap(tmp_path, ttl, ok):
    import subprocess
    import sys
    path = tmp_path / "t0-go.json"
    proc = subprocess.run(
        [sys.executable, str(ISSUER), "--decision-id", "T0-DEC-TEST", "--scope", SESSION, "--ttl", ttl,
         "--path", str(path)],
        capture_output=True, text=True, timeout=30,
    )
    assert (proc.returncode == 0) == ok, proc.stderr
    assert path.exists() == ok
