"""KNOWN GAPS: these are not security acceptance tests.

Each test pins current behaviour that is unsafe, or not proven safe, and that
the hook cannot close on its own. A passing test here means "the gap is still
exactly as documented", never "this is protected". When a gap is closed,
delete its test here and add an acceptance test in test_pre_tool_guard.py /
test_harness_failures.py that asserts the new, safe behaviour.

T12, the TTL bound, the T11 matcher gaps and the plain-text T10 paths are
closed and tested as acceptance tests. What remains needs an authorization
boundary the agent cannot cross (docs/adr/0001-authorization-boundary.md):
a hook narrows which tools an agent can use; it is not an identity check.

Run separately: python -m pytest tests/python -m known_gap
"""

import json

import pytest

from conftest import valid_marker

pytestmark = pytest.mark.known_gap

CANON_BASE = "appVftexD3KJRcdij"
SESSION = "tblEZ6ctzSoTBsfCW"
ALLOW = 0


def mcp(tool_name, **tool_input):
    return {"tool_name": tool_name, "tool_input": tool_input}


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


# --- T9: replay on hook-only write paths ------------------------------------
# Only the sfx-* MCP servers consume a marker. Every other path the hook
# gates (GitHub, Supabase, Notion, generic Airtable, Bash) only checks it, so
# one marker allows unlimited calls until it expires (at most MAX_TTL_SECONDS).

@pytest.mark.parametrize(
    "tool, scope",
    [
        ("mcp__github__push_files", "github:write"),
        ("mcp__Supabase__apply_migration", "supabase:apply_migration"),
        ("mcp__Supabase__execute_sql", "supabase:execute_sql"),
        ("mcp__Notion__notion-update-page", "notion:write"),
    ],
)
def test_gap_t9_hook_only_paths_never_consume_the_marker(run_hook, marker_path, tool, scope):
    marker_path.write_text(json.dumps(valid_marker([scope])))
    before = marker_path.read_text()
    assert [run_hook(mcp(tool)).returncode for _ in range(3)] == [ALLOW, ALLOW, ALLOW]
    assert marker_path.read_text() == before


# --- T10: the agent session can still create its own marker ------------------
# Plain references to the marker and the issuer are blocked. An agent that
# builds the path at runtime, or turns the hook off, is not. Nothing here is
# executed: the hook only inspects the command string.

@pytest.mark.parametrize(
    "command",
    [
        "python3 -c \"open('.claude/t0'+'-go.json','w').write('{}')\"",
        "printf '{}' > \"$(echo LmNsYXVkZS90MC1nby5qc29u | base64 -d)\"",
        "cp /tmp/m.json .claude/t0-g?.json",
    ],
)
def test_gap_t10_obfuscated_marker_writes_pass(run_hook, command):
    assert run_hook(bash(command)).returncode == ALLOW


@pytest.mark.parametrize("path", [".claude/settings.json", ".claude/settings.local.json", "hooks/pre_tool_guard.py"])
def test_gap_t10_agent_can_edit_the_hook_or_its_registration(run_hook, path):
    assert run_hook({"tool_name": "Edit", "tool_input": {"file_path": path}}).returncode == ALLOW


# --- T11: write paths the hook cannot see the target of -----------------------

@pytest.mark.parametrize(
    "payload",
    [
        mcp("mcp__Zapier__execute_zapier_write_action", selected_api="airtable", action="create_record"),
        mcp("mcp__Make__scenarios_run", scenarioId=1),
    ],
    ids=["zapier", "make"],
)
def test_gap_t11_generic_automation_connectors_can_write_airtable(run_hook, payload):
    assert run_hook(payload).returncode == ALLOW


@pytest.mark.parametrize("command", ["git push origin main", "gh api -X POST repos/o/r/merges -f base=main"])
def test_gap_t11_github_writes_over_bash_are_not_gated(run_hook, command):
    assert run_hook(bash(command)).returncode == ALLOW
